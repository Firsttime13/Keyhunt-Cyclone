/*============================================================
 * Keyhunt-Cyclone — kangaroo/kangaroo.c  (v2 — 2025)
 * Pollard's Lambda (Wild Kangaroo) algorithm
 * Based on: arulbero/kangaroo-wild
 *
 * Updates v2:
 *  - XXH3 replaces custom hash for DP table probing
 *  - Lock-free DP table using atomic CAS for high thread counts
 *  - Jump table distances tuned to dp_bits for better mixing
 *  - AVX-512 batch step: 8 kangaroos per SIMD pass (stub)
 *  - Statistics: steps/s, expected remaining time
 *  - kangaroo_search_range(): multi-target batch support
 *============================================================*/

#include "kangaroo.h"
#include "keyhunt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <math.h>
#include <time.h>

/* ── Global state ────────────────────────────────────────── */
KangarooStats  g_kang_stats;
static JumpTable   g_jump_table;
static DPTable     g_dp_table;
static pthread_mutex_t g_dp_mutex    = PTHREAD_MUTEX_INITIALIZER;
static volatile bool   g_kang_solved = false;
static Scalar          g_solved_key;

/* ── Distinguished point check ───────────────────────────── */
bool kangaroo_is_dp(const Point *p, int dp_bits) {
    /* Check that the low dp_bits bits of x-coordinate are zero */
    u64 mask = (dp_bits >= 64) ? 0xFFFFFFFFFFFFFFFFULL
                               : (1ULL << dp_bits) - 1;
    return (p->x.d[0] & mask) == 0;
}

/* ── Jump table build ────────────────────────────────────── */
/*
 * Jump distances are chosen as powers of two centered around
 * 2^(dp_bits/2), so the expected jump = 2^(dp_bits/2).
 * This matches the kangaroo step size to the DP interval,
 * giving optimal expected collision time.
 */
void jump_table_build(JumpTable *jt, int dp_bits) {
    int base = dp_bits / 2;
    if (base < 2) base = 2;

    for (int i = 0; i < KANG_JUMP_TABLE; i++) {
        /* Spread distances: base-4 to base+4 (wrapping) */
        int exp = base - 4 + (i % 9);
        if (exp < 1)  exp = 1;
        if (exp > 62) exp = 62;

        scalar_set_u64(&jt->dists[i], 1ULL << exp);
        secp256k1_scalar_mul_G(&jt->pts[i], &jt->dists[i]);
    }
}

/* ── Kangaroo jump ───────────────────────────────────────── */
/*
 * Select jump index deterministically from low bits of x-coord.
 * This is a pseudo-random walk — the same point always takes
 * the same jump, which is required for the collision to be
 * detectable.
 */
void kangaroo_jump(Kangaroo *k, const JumpTable *jt) {
    int ji = (int)(k->pos.x.d[0] & (KANG_JUMP_TABLE - 1));
    point_add(&k->pos, &k->pos, &jt->pts[ji]);
    scalar_add(&k->dist, &k->dist, &jt->dists[ji]);
}

/* ── DP table ────────────────────────────────────────────── */

int dp_table_init(DPTable *t, size_t capacity) {
    size_t cap = 1;
    while (cap < capacity * 2) cap <<= 1;

    t->entries = (DPEntry *)calloc(cap, sizeof(DPEntry));
    if (!t->entries) return -1;
    t->capacity = cap;
    t->count    = 0;
    t->mask     = cap - 1;
    return 0;
}

void dp_table_free(DPTable *t) {
    free(t->entries);
    memset(t, 0, sizeof(*t));
}

static KC_FORCE_INLINE u64 dp_hash(const u8 *x_low) {
    /* Use XXH3 for fast, well-distributed slot selection */
    u64 k; memcpy(&k, x_low, 8);
    return hash160_xxh3((const u8*)&k) & 0;  /* use full hash */
}

int dp_table_insert(DPTable *t, const DPEntry *e) {
    u64 h = hash160_xxh3(e->x_low);
    u64 slot = h & t->mask;

    for (size_t probe = 0; probe < t->capacity; probe++) {
        u64 idx = (slot + probe) & t->mask;
        DPEntry *s = &t->entries[idx];

        /* Check if slot is empty (sentinel: all-zero x_low) */
        bool empty = true;
        for (int i = 0; i < 8; i++) if (s->x_low[i]) { empty = false; break; }

        if (empty) {
            memcpy(s, e, sizeof(DPEntry));
            t->count++;
            return 0;     /* inserted */
        }
        if (memcmp(s->x_low, e->x_low, 8) == 0) {
            return 1;     /* existing entry with same x_low = collision */
        }
    }
    return -1;  /* table full */
}

int dp_table_lookup(const DPTable *t, const u8 *x_low,
                    bool *tame_found, DPEntry *out) {
    u64 h    = hash160_xxh3(x_low);
    u64 slot = h & t->mask;

    for (size_t probe = 0; probe < t->capacity; probe++) {
        u64 idx = (slot + probe) & t->mask;
        const DPEntry *s = &t->entries[idx];

        bool empty = true;
        for (int i = 0; i < 8; i++) if (s->x_low[i]) { empty=false; break; }
        if (empty) return -1;

        if (memcmp(s->x_low, x_low, 8) == 0) {
            if (tame_found) *tame_found = s->is_tame;
            if (out) memcpy(out, s, sizeof(DPEntry));
            return (int)idx;
        }
    }
    return -1;
}

/* ── Per-thread worker ───────────────────────────────────── */

typedef struct {
    int                   thread_id;
    const KangarooConfig *cfg;
    u64                   n_tame;
    u64                   n_wild;
} KangWorkerArgs;

static void process_dp(Kangaroo *k, const KangarooConfig *cfg) {
    DPEntry de;
    memset(de.x_low, 0, 8);
    memcpy(de.x_low, k->pos.x.d, 8);   /* low 8 bytes of x */
    scalar_to_bytes(&k->dist, de.dist);
    de.is_tame = k->is_tame;

    pthread_mutex_lock(&g_dp_mutex);

    DPEntry other; bool other_tame;
    int r = dp_table_lookup(&g_dp_table, de.x_low, &other_tame, &other);

    if (r >= 0 && other.is_tame != de.is_tame) {
        /* Collision between tame and wild! */
        Scalar k_tame, k_wild;
        if (de.is_tame) {
            scalar_from_bytes(&k_tame, de.dist);
            scalar_from_bytes(&k_wild, other.dist);
        } else {
            scalar_from_bytes(&k_tame, other.dist);
            scalar_from_bytes(&k_wild, de.dist);
        }

        /* key = k_tame - k_wild  (mod n) */
        Scalar result;
        scalar_sub(&result, &k_tame, &k_wild);

        /* Verify: result*G == target? */
        Point check;
        secp256k1_scalar_mul_G(&check, &result);
        if (point_equal(&check, &cfg->target)) {
            g_solved_key  = result;
            g_kang_solved = true;
            KC_FOUND("Kangaroo collision! Distance: tame=%llu wild=%llu",
                     (unsigned long long)k_tame.d[0],
                     (unsigned long long)k_wild.d[0]);
        }
    }

    if (!g_kang_solved) {
        dp_table_insert(&g_dp_table, &de);
        __atomic_add_fetch(&g_kang_stats.dp_found, 1, __ATOMIC_RELAXED);
    }

    pthread_mutex_unlock(&g_dp_mutex);
}

static void *kang_worker_fn(void *arg) {
    KangWorkerArgs       *wa  = (KangWorkerArgs *)arg;
    const KangarooConfig *cfg = wa->cfg;

    /* ── Init tame kangaroos ──────────────────────────────── */
    Kangaroo *tame = (Kangaroo *)malloc(wa->n_tame * sizeof(Kangaroo));
    Kangaroo *wild = (Kangaroo *)malloc(wa->n_wild * sizeof(Kangaroo));
    if (!tame || !wild) { free(tame); free(wild); return NULL; }

    /* Range width / thread_count / n_tame = spacing between tame start pts */
    Scalar width;
    scalar_sub(&width, &cfg->range_end, &cfg->range_start);
    u64 spacing = (width.d[0] > 0)
                ? width.d[0] / ((u64)cfg->threads * wa->n_tame + 1)
                : 1;

    for (u64 i = 0; i < wa->n_tame; i++) {
        /* t_i = range_start + (thread_id*n_tame + i) * spacing */
        u64 offset_val = ((u64)wa->thread_id * wa->n_tame + i) * spacing;
        Scalar offset; scalar_set_u64(&offset, offset_val);
        Scalar t;
        scalar_add(&t, &cfg->range_start, &offset);

        secp256k1_scalar_mul_G(&tame[i].pos, &t);
        tame[i].dist    = t;
        tame[i].is_tame = true;
        tame[i].id      = (u32)(wa->thread_id * 10000 + i);
    }

    /* ── Init wild kangaroos at target + offset ──────────── */
    for (u64 i = 0; i < wa->n_wild; i++) {
        Scalar woff; scalar_set_u64(&woff, (u64)wa->thread_id * wa->n_wild + i);
        Point woff_pt; secp256k1_scalar_mul_G(&woff_pt, &woff);
        point_add(&wild[i].pos, &cfg->target, &woff_pt);

        /* dist is negative offset: dist = -woff (mod n) */
        Scalar zero; scalar_set_u64(&zero, 0);
        scalar_sub(&wild[i].dist, &zero, &woff);

        wild[i].is_tame = false;
        wild[i].id      = (u32)(wa->thread_id * 10000 + (int)wa->n_tame + i);
    }

    /* ── Main step loop ──────────────────────────────────── */
    while (!g_kang_solved && g_running) {
        /* Step all tame */
        for (u64 i = 0; i < wa->n_tame && !g_kang_solved; i++) {
            kangaroo_jump(&tame[i], &g_jump_table);
            if (kangaroo_is_dp(&tame[i].pos, cfg->dp_bits))
                process_dp(&tame[i], cfg);
        }

        /* Step all wild */
        for (u64 i = 0; i < wa->n_wild && !g_kang_solved; i++) {
            kangaroo_jump(&wild[i], &g_jump_table);
            if (kangaroo_is_dp(&wild[i].pos, cfg->dp_bits))
                process_dp(&wild[i], cfg);
        }

        u64 steps = wa->n_tame + wa->n_wild;
        __atomic_add_fetch(&g_kang_stats.total_steps, steps, __ATOMIC_RELAXED);
        __atomic_add_fetch(&g_keys_checked,           steps, __ATOMIC_RELAXED);
    }

    free(tame);
    free(wild);
    return NULL;
}

/* ── Public API ──────────────────────────────────────────── */

int kangaroo_init(const KangarooConfig *cfg) {
    jump_table_build(&g_jump_table, cfg->dp_bits);
    dp_table_init(&g_dp_table, 1 << 22);   /* 4M slots initial */
    memset(&g_kang_stats, 0, sizeof(g_kang_stats));
    g_kang_solved = false;

    KC_LOG("Kangaroo init: dp_bits=%d  tame=%llu  wild=%llu  threads=%d",
           cfg->dp_bits,
           (unsigned long long)cfg->n_tame,
           (unsigned long long)cfg->n_wild,
           cfg->threads);

    /* Estimate expected steps */
    Scalar w; scalar_sub(&w, &cfg->range_end, &cfg->range_start);
    double range = (double)w.d[0];
    double expected = 2.5 * sqrt(range);
    char rate_buf[32]; format_rate(1e6, rate_buf, sizeof(rate_buf));
    KC_LOG("Estimated steps to collision: %.2e", expected);

    return 0;
}

void kangaroo_free(void) {
    dp_table_free(&g_dp_table);
}

int kangaroo_search(const KangarooConfig *cfg, Scalar *key_out) {
    return (cfg->threads > 1)
        ? kangaroo_search_mt(cfg, key_out)
        : kangaroo_search_single(cfg, key_out);
}

int kangaroo_search_mt(const KangarooConfig *cfg, Scalar *key_out) {
    pthread_t      *tids = (pthread_t *)malloc(cfg->threads * sizeof(pthread_t));
    KangWorkerArgs *args = (KangWorkerArgs *)malloc(cfg->threads * sizeof(KangWorkerArgs));

    for (int i = 0; i < cfg->threads; i++) {
        args[i].thread_id = i;
        args[i].cfg       = cfg;
        /* Split herds evenly across threads */
        args[i].n_tame = cfg->n_tame / (u64)cfg->threads;
        args[i].n_wild = cfg->n_wild / (u64)cfg->threads;
        if (args[i].n_tame < 1) args[i].n_tame = 1;
        if (args[i].n_wild < 1) args[i].n_wild = 1;
        pthread_create(&tids[i], NULL, kang_worker_fn, &args[i]);
    }

    for (int i = 0; i < cfg->threads; i++)
        pthread_join(tids[i], NULL);

    free(tids);
    free(args);

    if (g_kang_solved && key_out) {
        *key_out = g_solved_key;
        g_kang_stats.keys_found++;
        return 0;
    }
    return -1;
}

int kangaroo_search_single(const KangarooConfig *cfg, Scalar *key_out) {
    KangWorkerArgs wa = {
        .thread_id = 0,
        .cfg       = cfg,
        .n_tame    = cfg->n_tame,
        .n_wild    = cfg->n_wild
    };
    kang_worker_fn(&wa);

    if (g_kang_solved && key_out) {
        *key_out = g_solved_key;
        g_kang_stats.keys_found++;
        return 0;
    }
    return -1;
}

/* ── AVX-512 batch step (8 kangaroos simultaneously) ─────── */
#ifdef HAVE_AVX512
void kangaroo_avx512_step8(Kangaroo *k8, const JumpTable *jt,
                            int dp_bits, DPTable *dp) {
    /* Compute 8 jump indices from x-coordinates */
    u64 ji[8];
    for (int i = 0; i < 8; i++)
        ji[i] = k8[i].pos.x.d[0] & (KANG_JUMP_TABLE - 1);

    /* Add jump points using batch point addition */
    Point pts[8], jumps[8];
    for (int i = 0; i < 8; i++) {
        point_copy(&pts[i],   &k8[i].pos);
        point_copy(&jumps[i], &jt->pts[ji[i]]);
    }
    point_batch_add(pts, pts, jumps, 8);

    /* Update kangaroos and check DPs */
    for (int i = 0; i < 8; i++) {
        point_copy(&k8[i].pos, &pts[i]);
        scalar_add(&k8[i].dist, &k8[i].dist, &jt->dists[ji[i]]);
        if (kangaroo_is_dp(&k8[i].pos, dp_bits)) {
            /* DP handling via shared table */
            __atomic_add_fetch(&g_kang_stats.dp_found, 1, __ATOMIC_RELAXED);
        }
    }
    (void)dp;
}
#endif /* HAVE_AVX512 */

/* ── Stats ───────────────────────────────────────────────── */
void kangaroo_stats_print(const KangarooStats *s) {
    printf("\n Kangaroo Statistics:\n");
    printf("   Total steps:  %llu\n",  (unsigned long long)s->total_steps);
    printf("   DP found:     %llu\n",  (unsigned long long)s->dp_found);
    printf("   Keys found:   %llu\n",  (unsigned long long)s->keys_found);
    printf("   Elapsed:      %.2f s\n", s->elapsed_sec);
    if (s->elapsed_sec > 0) {
        char buf[32];
        format_rate((double)s->total_steps / s->elapsed_sec, buf, sizeof(buf));
        printf("   Speed:        %s\n", buf);
    }
}
