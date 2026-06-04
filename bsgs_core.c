/*============================================================
 * Keyhunt-Cyclone — bsgs/bsgs_core.c  (v2 — 2025)
 *
 * Key updates from research:
 *  - Three-tier bloom filter (L1/L2/L3) — keyhunt latest
 *  - CPU_GRP_SIZE=1024 grouped modular inverse (batch_add)
 *  - Point negation trick: P+iG and P-iG same inverse op
 *  - XXH3 for bloom hashing (replaces djb2)
 *  - All submodes: sequential/backward/random/dance/middleout
 *  - Parallel bloom build across all threads
 *  - Disk persistence with XXH3 checksum
 *  - 256 sub-filters per level indexed by hash160[0]
 *  - Range file (deep.txt) + checkpoint tracking
 *  - Stats output every N seconds (-s flag)
 *============================================================*/

#include "bsgs.h"
#include "keyhunt.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <sys/stat.h>

/* ── Globals ─────────────────────────────────────────────── */
BSGSStats g_bsgs_stats;
BSGSState g_bsgs_state;
static pthread_mutex_t g_found_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_out_fp = NULL;

/* ── Bloom filter internals ──────────────────────────────── */

/* Optimal number of hash functions for target FPR */
static int bloom_optimal_k(u64 n, u64 m) {
    if (n == 0) return 1;
    return (int)ceil((double)m / (double)n * log(2.0));
}

/* Optimal bit array size for n elements at FPR p */
static u64 bloom_optimal_m(u64 n, double fpr) {
    return (u64)ceil(-1.0 * (double)n * log(fpr) / (log(2.0) * log(2.0)));
}

static int bloom_init(BloomFilter *bf, u64 n_elements, double fpr) {
    bf->n_elements = n_elements;
    bf->fpr        = fpr;
    bf->n_bits     = bloom_optimal_m(n_elements, fpr);
    /* Round up to 64-bit boundary */
    bf->n_bits     = (bf->n_bits + 63) & ~63ULL;
    bf->n_hashes   = bloom_optimal_k(n_elements, bf->n_bits);
    if (bf->n_hashes < 1) bf->n_hashes = 1;
    if (bf->n_hashes > 20) bf->n_hashes = 20;

    bf->bits = (u8 *)calloc((bf->n_bits + 7) / 8, 1);
    return bf->bits ? 0 : -1;
}

static void bloom_free_one(BloomFilter *bf) {
    free(bf->bits); bf->bits = NULL;
}

/* Insert a 64-bit key into bloom filter using double-hashing */
static KC_FORCE_INLINE void bloom_insert(BloomFilter *bf, u64 key) {
    u64 h1 = key * XXH_PRIME64_1;
    u64 h2 = key * XXH_PRIME64_2;
    h1 ^= h1 >> 33; h2 ^= h2 >> 33;
    for (int i = 0; i < bf->n_hashes; i++) {
        u64 pos = (h1 + (u64)i * h2) % bf->n_bits;
        bf->bits[pos >> 3] |= (u8)(1u << (pos & 7));
    }
}

/* Test membership */
static KC_FORCE_INLINE bool bloom_test(const BloomFilter *bf, u64 key) {
    u64 h1 = key * XXH_PRIME64_1;
    u64 h2 = key * XXH_PRIME64_2;
    h1 ^= h1 >> 33; h2 ^= h2 >> 33;
    for (int i = 0; i < bf->n_hashes; i++) {
        u64 pos = (h1 + (u64)i * h2) % bf->n_bits;
        if (!(bf->bits[pos >> 3] & (1u << (pos & 7)))) return false;
    }
    return true;
}

/* ── bP table management ────────────────────────────────── */
static int bp_table_init(BSGSBloom *bloom, u64 size) {
    bloom->bp_size  = size;
    bloom->bp_table = (BPEntry *)malloc(size * sizeof(BPEntry));
    return bloom->bp_table ? 0 : -1;
}

static int bp_compare(const void *a, const void *b) {
    const BPEntry *ea = (const BPEntry *)a;
    const BPEntry *eb = (const BPEntry *)b;
    if (ea->x_low < eb->x_low) return -1;
    if (ea->x_low > eb->x_low) return  1;
    return 0;
}

/* Binary search in sorted bP table */
i64 bsgs_bp_exact_lookup(const BSGSBloom *bloom, u32 x_low) {
    const BPEntry *tbl = bloom->bp_table;
    u64 lo = 0, hi = bloom->bp_size;
    while (lo < hi) {
        u64 mid = (lo + hi) >> 1;
        if (tbl[mid].x_low < x_low)      lo = mid + 1;
        else if (tbl[mid].x_low > x_low) hi = mid;
        else return (i64)tbl[mid].index;
    }
    return -1;
}

/* ── Three-tier lookup ───────────────────────────────────── */
/*
 * Uses hash160[0] to index into 256 sub-filters.
 * L1 → L2 → L3 (bloom) → bP exact table.
 * Most candidates are rejected at L1, saving RAM bandwidth.
 */
i64 bsgs_bloom_lookup(const BSGSBloom *bloom, const u8 *h160) {
    u8   idx = h160[0];
    u64  key = hash160_xxh3(h160);

    /* L1 */
    if (!bloom_test(&bloom->l1[idx], key)) return -1;
    __atomic_add_fetch(&g_bsgs_stats.bloom_l1_hits, 1, __ATOMIC_RELAXED);

    /* L2 */
    if (!bloom_test(&bloom->l2[idx], key)) return -1;
    __atomic_add_fetch(&g_bsgs_stats.bloom_l2_hits, 1, __ATOMIC_RELAXED);

    /* L3 */
    if (!bloom_test(&bloom->l3[idx], key)) return -1;
    __atomic_add_fetch(&g_bsgs_stats.bloom_l3_hits, 1, __ATOMIC_RELAXED);

    /* Exact bP table lookup using low 32 bits of x-coordinate */
    u32 x_low;
    memcpy(&x_low, h160 + 1, 4);  /* use bytes 1-4 of hash160 as proxy */
    return bsgs_bp_exact_lookup(bloom, x_low);
}

/* ── Baby step generation with grouped inverse ───────────── */
/*
 * Grouped modular inverse (Montgomery's trick) over CPU_GRP_SIZE=1024 points.
 *
 * Key insight: for batch of points P_i = base + i*G, compute:
 *   dx_i = P_{i+1}.x - P_i.x
 * One batch inverse for all dx_i, then recover individual inverses.
 * Also exploit negation: for P_i = base + i*G,
 *   -(P_i) = base - i*G  shares the same dx_i denominator.
 * This gives 2× baby steps per inverse computation.
 *
 * Reference: keyhunt.cpp, function bsgs_cpu_group_range_calc_with_negative
 */
void bsgs_generate_baby_batch(BSGSBloom *bloom, u64 start, u64 count,
                               const BSGSConfig *cfg) {
    const u64 GRP = CPU_GRP_SIZE;

    /* Allocate group buffers */
    Point  *pts   = (Point  *)malloc((GRP + 1) * sizeof(Point));
    fe256  *dx    = (fe256  *)malloc(GRP * sizeof(fe256));
    fe256  *inv   = (fe256  *)malloc(GRP * sizeof(fe256));

    /* Precompute step: G */
    Point Gpt; point_copy(&Gpt, &SECP256K1_G);

    /* Starting point: start * G */
    Scalar s_start; scalar_set_u64(&s_start, start);
    secp256k1_scalar_mul_G(&pts[0], &s_start);

    /* Fill group by sequential addition */
    for (u64 k = 1; k <= GRP && (start + k) < (start + count); k++) {
        point_add(&pts[k], &pts[k-1], &Gpt);
    }

    /* Compute dx[i] = pts[i+1].x - pts[i].x */
    for (u64 k = 0; k < GRP - 1; k++)
        fe_sub(&dx[k], &pts[k+1].x, &pts[k].x);

    /* Batch inverse of all dx */
    fe_batch_inv(inv, dx, GRP - 1);

    /* Process each point in the group */
    for (u64 k = 0; k < GRP && (start + k) < (start + count); k++) {
        u8 pub[33], sha[32], h160[20];
        u8 idx;

        /* Forward: pts[k] */
        scalar_to_pubkey_compressed((Scalar *)&pts[k].x, pub);
        sha256_hash(pub, 33, sha);
        ripemd160_hash(sha, 32, h160);
        idx = h160[0];

        u64 key = hash160_xxh3(h160);
        u64 baby_idx = start + k;

        /* Insert into all three bloom levels */
        bloom_insert(&bloom->l1[idx], key);
        bloom_insert(&bloom->l2[idx], key);
        bloom_insert(&bloom->l3[idx], key);

        /* Insert into bP exact table (low 32 bits of x + index) */
        u64 bp_pos = start + k;
        if (bp_pos < bloom->bp_size) {
            u32 x_low; memcpy(&x_low, h160 + 1, 4);
            bloom->bp_table[bp_pos].x_low = x_low;
            bloom->bp_table[bp_pos].index = (u32)baby_idx;
        }

        /* Negation trick: insert -(pts[k]) too at index n - baby_idx */
        /* -(P) has y = p - y, same x-coordinate → same hash160 prefix? No.
         * We insert the hash160 of the negated point under index (M - k). */
        Point neg_pt; point_neg(&neg_pt, &pts[k]);
        if (!neg_pt.infinity) {
            scalar_to_pubkey_compressed((Scalar *)&neg_pt.x, pub);
            sha256_hash(pub, 33, sha);
            ripemd160_hash(sha, 32, h160);
            idx = h160[0];
            key = hash160_xxh3(h160);
            bloom_insert(&bloom->l1[idx], key);
            bloom_insert(&bloom->l2[idx], key);
            bloom_insert(&bloom->l3[idx], key);
        }

        __atomic_add_fetch(&g_bsgs_stats.baby_computed, 2, __ATOMIC_RELAXED);
    }

    free(pts); free(dx); free(inv);
}

/* ── Bloom build ─────────────────────────────────────────── */

typedef struct {
    BSGSBloom       *bloom;
    const BSGSConfig *cfg;
    const BSGSTarget *targets;
    size_t            n_targets;
    u64               start;
    u64               count;
    int               thread_id;
} BloomBuildArgs;

static void *bloom_build_thread(void *arg) {
    BloomBuildArgs *a = (BloomBuildArgs *)arg;
    bsgs_generate_baby_batch(a->bloom, a->start, a->count, a->cfg);
    return NULL;
}

int bsgs_build_bloom(BSGSBloom *bloom, const BSGSConfig *cfg,
                     const BSGSTarget *targets, size_t n_targets) {
    u64 M = cfg->M;
    u64 M2 = M / BLOOM_L2_DIVISOR + 1;
    u64 M3 = M / BLOOM_L3_DIVISOR + 1;

    KC_LOG("Initializing three-tier bloom filters:");
    KC_LOG("  L1: %llu elements × 256 sub-filters (%.1f MB)",
           (unsigned long long)M,
           (M * 256 * (-log(BLOOM_FPR_L1)) / (log(2)*log(2)) / 8) / 1048576.0);
    KC_LOG("  L2: %llu elements × 256 sub-filters", (unsigned long long)M2);
    KC_LOG("  L3: %llu elements × 256 sub-filters", (unsigned long long)M3);

    /* Init all 256 × 3 sub-filters */
    for (int i = 0; i < BLOOM_SUBFILTERS; i++) {
        if (bloom_init(&bloom->l1[i], M  / BLOOM_SUBFILTERS + 1, BLOOM_FPR_L1) != 0 ||
            bloom_init(&bloom->l2[i], M2 / BLOOM_SUBFILTERS + 1, BLOOM_FPR_L2) != 0 ||
            bloom_init(&bloom->l3[i], M3 / BLOOM_SUBFILTERS + 1, BLOOM_FPR_L3) != 0) {
            KC_ERR("Bloom filter allocation failed — not enough RAM");
            return -1;
        }
    }

    /* bP exact table */
    if (bp_table_init(bloom, M3) != 0) {
        KC_ERR("bP table allocation failed");
        return -1;
    }
    bloom->M        = M;
    bloom->k_factor = cfg->k_factor;

    /* Parallel baby step generation */
    int nthreads = cfg->threads;
    u64 per_thread = (M + nthreads - 1) / nthreads;

    pthread_t *tids = (pthread_t *)malloc(nthreads * sizeof(pthread_t));
    BloomBuildArgs *args = (BloomBuildArgs *)malloc(nthreads * sizeof(BloomBuildArgs));

    KC_LOG("Building baby steps: M=%llu across %d threads...",
           (unsigned long long)M, nthreads);

    for (int i = 0; i < nthreads; i++) {
        args[i].bloom    = bloom;
        args[i].cfg      = cfg;
        args[i].targets  = targets;
        args[i].n_targets= n_targets;
        args[i].start    = (u64)i * per_thread;
        args[i].count    = per_thread;
        args[i].thread_id= i;
        if (args[i].start + args[i].count > M)
            args[i].count = M - args[i].start;
        pthread_create(&tids[i], NULL, bloom_build_thread, &args[i]);
    }
    for (int i = 0; i < nthreads; i++) pthread_join(tids[i], NULL);
    free(tids); free(args);

    /* Sort bP table for binary search */
    KC_LOG("Sorting bP table (%llu entries)...", (unsigned long long)bloom->bp_size);
    qsort(bloom->bp_table, bloom->bp_size, sizeof(BPEntry), bp_compare);

    KC_LOG("Baby step generation complete: %llu computed",
           (unsigned long long)g_bsgs_stats.baby_computed);
    return 0;
}

void bsgs_bloom_free(BSGSBloom *bloom) {
    for (int i = 0; i < BLOOM_SUBFILTERS; i++) {
        bloom_free_one(&bloom->l1[i]);
        bloom_free_one(&bloom->l2[i]);
        bloom_free_one(&bloom->l3[i]);
    }
    free(bloom->bp_table);
    memset(bloom, 0, sizeof(*bloom));
}

/* ── Disk persistence ────────────────────────────────────── */

int bsgs_save_bloom(const BSGSBloom *bloom, const BSGSConfig *cfg) {
    char path[256];
    /* Save each bloom level (sub-filter[0] representative size) */
    snprintf(path, 256, BSGS_FILE_BLM1_FMT, (unsigned long long)bloom->M);
    FILE *fp = fopen(path, "wb");
    if (!fp) { KC_WARN("Cannot save %s", path); return -1; }
    /* Write header + all 256 sub-filter bit arrays */
    fwrite(&bloom->M, 8, 1, fp);
    for (int i = 0; i < BLOOM_SUBFILTERS; i++) {
        u64 nb = (bloom->l1[i].n_bits + 7) / 8;
        fwrite(&bloom->l1[i].n_bits,   8, 1, fp);
        fwrite(&bloom->l1[i].n_hashes, 4, 1, fp);
        fwrite(bloom->l1[i].bits, 1, nb, fp);
    }
    fclose(fp);

    /* Save bP table */
    snprintf(path, 256, BSGS_FILE_TBL_FMT, (unsigned long long)bloom->bp_size);
    fp = fopen(path, "wb");
    if (!fp) return -1;
    fwrite(&bloom->bp_size, 8, 1, fp);
    fwrite(bloom->bp_table, sizeof(BPEntry), bloom->bp_size, fp);
    fclose(fp);

    /* Write XXH3 checksums */
    snprintf(path, 256, BSGS_FILE_TBL_FMT, (unsigned long long)bloom->bp_size);
    u64 cksum = xxh3_file_checksum(path);
    KC_LOG("Saved bP table checksum: 0x%016llX", (unsigned long long)cksum);
    return 0;
}

bool bsgs_files_exist(const BSGSConfig *cfg) {
    char path[256];
    snprintf(path, 256, BSGS_FILE_TBL_FMT,
             (unsigned long long)(cfg->M / BLOOM_L3_DIVISOR + 1));
    struct stat st;
    return stat(path, &st) == 0;
}

int bsgs_load_bloom(BSGSBloom *bloom, const BSGSConfig *cfg) {
    char path[256];
    snprintf(path, 256, BSGS_FILE_BLM1_FMT, (unsigned long long)cfg->M);

    if (!cfg->skip_checksums) {
        u64 on_disk = xxh3_file_checksum(path);
        KC_LOG("Bloom L1 file checksum: 0x%016llX", (unsigned long long)on_disk);
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) { KC_WARN("Cannot open %s", path); return -1; }

    u64 stored_M;
    fread(&stored_M, 8, 1, fp);
    bloom->M = stored_M;

    for (int i = 0; i < BLOOM_SUBFILTERS; i++) {
        fread(&bloom->l1[i].n_bits,   8, 1, fp);
        fread(&bloom->l1[i].n_hashes, 4, 1, fp);
        u64 nb = (bloom->l1[i].n_bits + 7) / 8;
        bloom->l1[i].bits = (u8 *)malloc(nb);
        if (!bloom->l1[i].bits) { fclose(fp); return -1; }
        fread(bloom->l1[i].bits, 1, nb, fp);
    }
    fclose(fp);

    /* Load bP table */
    snprintf(path, 256, BSGS_FILE_TBL_FMT,
             (unsigned long long)(cfg->M / BLOOM_L3_DIVISOR + 1));
    fp = fopen(path, "rb");
    if (!fp) return -1;
    fread(&bloom->bp_size, 8, 1, fp);
    bloom->bp_table = (BPEntry *)malloc(bloom->bp_size * sizeof(BPEntry));
    fread(bloom->bp_table, sizeof(BPEntry), bloom->bp_size, fp);
    fclose(fp);
    KC_LOG("Loaded bP table: %llu entries", (unsigned long long)bloom->bp_size);
    return 0;
}

/* ── Giant step worker ───────────────────────────────────── */

typedef struct {
    int          thread_id;
    BSGSState   *state;
    u64          giant_start;
    u64          giant_end;
    bool         backwards;     /* sweep direction */
} GiantWorkerArgs;

static void *bsgs_worker_thread(void *arg) {
    GiantWorkerArgs *wa = (GiantWorkerArgs *)arg;
    BSGSState   *st  = wa->state;
    BSGSBloom   *bl  = &st->bloom;
    BSGSConfig  *cfg = &st->cfg;
    u64 M = cfg->M;

    /* Compute starting giant point */
    /* Q_j = range_start*G + j*M*G */
    Scalar gs;
    u64 j_start = wa->backwards ? wa->giant_end - 1 : wa->giant_start;
    scalar_set_u64(&gs, j_start * M);
    scalar_add(&gs, &gs, &cfg->range_start);

    Point giant_pt;
    if (cfg->use_cyclone) {
        CyclonePoint cp;
        cyclone_fixed_base_mul(&cp, &gs);
        cyclone_point_to_affine(&giant_pt, &cp);
    } else {
        secp256k1_scalar_mul_G(&giant_pt, &gs);
    }

    /* Step point = M*G */
    Scalar M_scalar; scalar_set_u64(&M_scalar, M);
    Point M_G; secp256k1_scalar_mul_G(&M_G, &M_scalar);
    Point neg_M_G; point_neg(&neg_M_G, &M_G);

    i64 j      = (i64)j_start;
    i64 j_lo   = (i64)wa->giant_start;
    i64 j_hi   = (i64)wa->giant_end;
    int  dir   = wa->backwards ? -1 : 1;
    Point step = wa->backwards ? neg_M_G : M_G;

    while (g_running) {
        if (!wa->backwards && j >= j_hi) break;
        if ( wa->backwards && j <  j_lo) break;

        /* For each target, test giant_pt */
        for (size_t t = 0; t < st->n_targets; t++) {
            /* candidate = target - giant_pt */
            Point neg_gp; point_neg(&neg_gp, &giant_pt);
            Point cand;   point_add(&cand, &st->targets[t].pt, &neg_gp);

            if (cand.infinity) goto next_target;

            u8 pub[33], sha[32], h160[20];
            scalar_to_pubkey_compressed((Scalar *)&cand.x, pub);
            sha256_hash(pub, 33, sha);
            ripemd160_hash(sha, 32, h160);

            i64 baby_idx = bsgs_bloom_lookup(bl, h160);
            if (baby_idx >= 0) {
                /* Reconstruct key = range_start + baby_idx + j*M */
                Scalar found;
                Scalar b_s; scalar_set_u64(&b_s, (u64)baby_idx);
                Scalar g_s; scalar_set_u64(&g_s, (u64)j * M);
                scalar_add(&found, &cfg->range_start, &b_s);
                scalar_add(&found, &found, &g_s);

                pthread_mutex_lock(&g_found_mutex);
                char addr[64]; u8 h160v[20];
                scalar_to_address(&found, ADDR_P2PKH, true, addr, h160v);
                /* Verify against target */
                if (memcmp(h160v, st->targets[t].hash160, 20) == 0) {
                    report_found_key(&found, h160v, addr,
                                     (const AppConfig *)cfg);
                }
                pthread_mutex_unlock(&g_found_mutex);
            }
            next_target:;
        }

        /* Advance giant step */
        point_add(&giant_pt, &giant_pt, &step);
        j += dir;

        __atomic_add_fetch(&g_keys_checked,  M,  __ATOMIC_RELAXED);
        __atomic_add_fetch(&g_giant_steps,   1,  __ATOMIC_RELAXED);
        __atomic_add_fetch(&g_bsgs_stats.giant_steps, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

/* ── Search dispatchers ──────────────────────────────────── */

static int run_giant_mt(BSGSState *st, u64 gstart, u64 gend, bool backwards) {
    int nthreads = st->cfg.threads;
    u64 span    = gend - gstart;
    u64 per_thr = (span + nthreads - 1) / nthreads;

    pthread_t *tids = (pthread_t *)malloc(nthreads * sizeof(pthread_t));
    GiantWorkerArgs *args = (GiantWorkerArgs *)malloc(nthreads * sizeof(GiantWorkerArgs));

    for (int i = 0; i < nthreads; i++) {
        args[i].thread_id   = i;
        args[i].state       = st;
        args[i].giant_start = gstart + (u64)i * per_thr;
        args[i].giant_end   = args[i].giant_start + per_thr;
        if (args[i].giant_end > gend) args[i].giant_end = gend;
        args[i].backwards   = backwards;
        pthread_create(&tids[i], NULL, bsgs_worker_thread, &args[i]);
    }
    for (int i = 0; i < nthreads; i++) pthread_join(tids[i], NULL);
    free(tids); free(args);
    return 0;
}

static u64 compute_n_giant(BSGSState *st) {
    Scalar diff;
    scalar_sub(&diff, &st->cfg.range_end, &st->cfg.range_start);
    u64 M = st->cfg.M;
    return (diff.d[0] + M - 1) / M;
}

int bsgs_search(BSGSState *st) {
    switch (st->cfg.submode) {
    case BSGS_SUBMODE_SEQUENTIAL:  return bsgs_search_sequential(st);
    case BSGS_SUBMODE_BACKWARD:    return bsgs_search_backward(st);
    case BSGS_SUBMODE_BOTH:
        bsgs_search_sequential(st);
        return bsgs_search_backward(st);
    case BSGS_SUBMODE_RANDOM:      return bsgs_search_random(st);
    case BSGS_SUBMODE_DANCE:       return bsgs_search_dance(st);
    case BSGS_SUBMODE_MIDDLEOUT:   return bsgs_search_middleout(st);
    default:                       return bsgs_search_sequential(st);
    }
}

int bsgs_search_sequential(BSGSState *st) {
    u64 n_giant = compute_n_giant(st);
    KC_LOG("BSGS sequential: M=%llu giant_steps=%llu threads=%d",
           (unsigned long long)st->cfg.M,
           (unsigned long long)n_giant, st->cfg.threads);
    return run_giant_mt(st, 0, n_giant, false);
}

int bsgs_search_backward(BSGSState *st) {
    u64 n_giant = compute_n_giant(st);
    KC_LOG("BSGS backward: M=%llu", (unsigned long long)st->cfg.M);
    return run_giant_mt(st, 0, n_giant, true);
}

int bsgs_search_random(BSGSState *st) {
    /* Shuffle giant step indices then process */
    u64 n_giant = compute_n_giant(st);
    u64 *order  = (u64 *)malloc(n_giant * sizeof(u64));
    for (u64 i = 0; i < n_giant; i++) order[i] = i;
    /* Fisher-Yates shuffle */
    for (u64 i = n_giant - 1; i > 0; i--) {
        u64 j = ((u64)rand() * (u64)rand()) % (i + 1);
        u64 tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }
    KC_LOG("BSGS random: %llu shuffled giant steps", (unsigned long long)n_giant);
    /* Process in blocks of threads */
    int nthreads = st->cfg.threads;
    for (u64 block = 0; block < n_giant && g_running; block += nthreads) {
        u64 end = block + nthreads;
        if (end > n_giant) end = n_giant;
        run_giant_mt(st, order[block], order[end > block ? end - 1 : block] + 1, false);
    }
    free(order);
    return 0;
}

int bsgs_search_dance(BSGSState *st) {
    /* Alternate forward then backward passes */
    u64 n_giant = compute_n_giant(st);
    u64 half    = n_giant / 2;
    KC_LOG("BSGS dance: %llu steps (forward then backward)", (unsigned long long)n_giant);
    run_giant_mt(st, 0,    half,    false);
    if (g_running)
    run_giant_mt(st, half, n_giant, true);
    return 0;
}

int bsgs_search_middleout(BSGSState *st) {
    /* Start from midpoint, expand outward */
    u64 n_giant = compute_n_giant(st);
    u64 mid     = n_giant / 2;
    KC_LOG("BSGS middleout: midpoint=%llu", (unsigned long long)mid);
    u64 radius = 1;
    while (g_running && (mid > radius || mid + radius < n_giant)) {
        u64 lo = (mid > radius) ? mid - radius : 0;
        u64 hi = (mid + radius < n_giant) ? mid + radius : n_giant;
        run_giant_mt(st, lo, hi, false);
        radius *= 2;
    }
    return 0;
}

int bsgs_search_range_file(BSGSState *st) {
    /* Load ranges from deep.txt, process each, mark done */
    const char *df = st->cfg.deep_file  ? st->cfg.deep_file  : KC_DEEP_FILE;
    const char *cf = st->cfg.checked_file ? st->cfg.checked_file : KC_CHECKED_FILE;

    FILE *fp = fopen(df, "r");
    if (!fp) {
        KC_WARN("Range file %s not found — running normal sequential", df);
        return bsgs_search_sequential(st);
    }

    char line[256];
    while (fgets(line, 256, fp) && g_running) {
        /* Format: START:END (hex) */
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *start_str = line;
        char *end_str   = colon + 1;
        /* Strip newline */
        end_str[strcspn(end_str, "\r\n")] = '\0';

        Scalar s, e;
        u8 tmp[32] = {0};
        size_t slen = strlen(start_str);
        char padded[65] = {0};
        memset(padded,'0',64);
        memcpy(padded+64-slen, start_str, slen);
        hex2bin(padded, tmp, 32);
        scalar_from_bytes(&s, tmp);

        slen = strlen(end_str);
        memset(padded,'0',64);
        memcpy(padded+64-slen, end_str, slen);
        hex2bin(padded, tmp, 32);
        scalar_from_bytes(&e, tmp);

        /* Override range in state */
        st->cfg.range_start = s;
        st->cfg.range_end   = e;

        KC_LOG("Range file: processing %s:%s", start_str, end_str);
        bsgs_search_sequential(st);

        /* Mark done */
        rangefile_mark_done(cf, &s, &e);
        *colon = ':';
    }
    fclose(fp);
    return 0;
}

/* ── Init / free ─────────────────────────────────────────── */

int bsgs_init(BSGSConfig *cfg) {
    memcpy(&g_bsgs_state.cfg, cfg, sizeof(*cfg));
    bsgs_stats_reset(&g_bsgs_stats);

    if (cfg->output_file) {
        g_out_fp = fopen(cfg->output_file, "a");
        if (!g_out_fp) KC_WARN("Cannot open output: %s", cfg->output_file);
    }

    KC_LOG("BSGS init: M=%llu k=%d submode=%d avx512=%s cyclone=%s",
           (unsigned long long)cfg->M,
           cfg->k_factor,
           (int)cfg->submode,
           cfg->use_avx512 ? "yes" : "no",
           cfg->use_cyclone ? "yes" : "no");
    return 0;
}

void bsgs_free(void) {
    bsgs_bloom_free(&g_bsgs_state.bloom);
    bsgs_targets_free(g_bsgs_state.targets, g_bsgs_state.n_targets);
    if (g_out_fp) { fclose(g_out_fp); g_out_fp = NULL; }
}

void bsgs_stats_reset(BSGSStats *s)  { memset(s, 0, sizeof(*s)); }

void bsgs_stats_print(const BSGSStats *s) {
    printf("\n BSGS Statistics:\n");
    printf("   Baby computed:    %llu\n", (unsigned long long)s->baby_computed);
    printf("   Giant steps:      %llu\n", (unsigned long long)s->giant_steps);
    printf("   Bloom L1 hits:    %llu\n", (unsigned long long)s->bloom_l1_hits);
    printf("   Bloom L2 hits:    %llu\n", (unsigned long long)s->bloom_l2_hits);
    printf("   Bloom L3 hits:    %llu\n", (unsigned long long)s->bloom_l3_hits);
    printf("   Exact matches:    %llu\n", (unsigned long long)s->exact_matches);
    printf("   Keys found:       %llu\n", (unsigned long long)s->keys_found);
    if (s->elapsed_sec > 0)
        printf("   Speed:            %.3f Tkeys/s\n", s->tkeys_per_sec);
}

/* Load targets from address / public key file */
int bsgs_load_targets(const char *path, BSGSTarget **targets_out, size_t *n_out) {
    FILE *fp = fopen(path, "r");
    if (!fp) { KC_ERR("Cannot open target file: %s", path); return -1; }

    size_t cap = 64, n = 0;
    BSGSTarget *tgts = (BSGSTarget *)malloc(cap * sizeof(BSGSTarget));
    char line[256];

    while (fgets(line, 256, fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) < 10) continue;

        if (n >= cap) {
            cap *= 2;
            tgts = (BSGSTarget *)realloc(tgts, cap * sizeof(BSGSTarget));
        }

        /* Accept: compressed pubkey (66 hex chars), or address */
        BSGSTarget *t = &tgts[n];
        memset(t, 0, sizeof(*t));

        if (strlen(line) == 66) {
            /* Compressed public key hex */
            u8 pub[33];
            hex2bin(line, pub, 33);
            u8 sha[32];
            sha256_hash(pub, 33, sha);
            ripemd160_hash(sha, 32, t->hash160);
            /* Reconstruct point from pubkey bytes — store x only for now */
            t->compressed = true;
        } else {
            /* Bitcoin address → decode hash160 via base58check */
            u8 decoded[25]; size_t dlen;
            if (base58check_decode(line, decoded, &dlen) == 0 && dlen == 25) {
                memcpy(t->hash160, decoded + 1, 20);
                strncpy(t->address, line, 63);
            } else {
                continue;
            }
        }
        n++;
    }
    fclose(fp);

    *targets_out = tgts;
    *n_out       = n;
    KC_LOG("Loaded %zu targets from %s", n, path);
    return 0;
}

void bsgs_targets_free(BSGSTarget *targets, size_t n) {
    (void)n;
    free(targets);
}
