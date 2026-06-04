#ifndef BSGS_H
#define BSGS_H

/*============================================================
 * Keyhunt-Cyclone — bsgs.h  (v2 — updated 2025)
 *
 * Updates vs v1:
 *  - Three-tier bloom filter (L1/L2/L3) per keyhunt latest
 *  - Submodes: sequential, backward, both, random, dance, middleout
 *  - CPU_GRP_SIZE=1024 grouped modular inverse batching
 *  - Point negation trick: P±iG same inverse (2× efficiency)
 *  - Disk persistence with XXH3 checksum verification
 *  - Parallel bloom filter loading across threads
 *  - WIF mask search mode (-w flag)
 *  - Range file (deep.txt) + checkpoint (checked-deep.txt)
 *  - k-factor tuning for RAM/speed tradeoff
 *  - 256 bloom sub-filters indexed by x-coord byte[0]
 *    (reduces lock contention in multi-thread scenarios)
 *============================================================*/

#include "common.h"
#include "secp256k1.h"
#include "cyclone.h"

/* ── Three-tier bloom filter sizes (relative to M) ─────── */
/* Level 1: M elements (catches most)
 * Level 2: M/32 elements (second pass)
 * Level 3: M/1024 elements (final, uses exact bP table)
 * The k-factor (-k) scales M: N = M * k_factor             */
#define BLOOM_L1_DIVISOR    1
#define BLOOM_L2_DIVISOR    32
#define BLOOM_L3_DIVISOR    1024

/* 256 sub-filters per level, indexed by hash160[0] */
#define BLOOM_SUBFILTERS    256

/* ── Bloom filter error rates ───────────────────────────── */
#define BLOOM_FPR_L1        0.000010   /* 0.001% */
#define BLOOM_FPR_L2        0.000010
#define BLOOM_FPR_L3        0.000001   /* 0.0001% */

/* ── bP table entry ─────────────────────────────────────── */
/* Stores (x-coordinate low 32 bits, baby index) for exact match */
typedef struct {
    u32  x_low;       /* low 32 bits of x-coordinate */
    u32  index;       /* baby step index i            */
} BPEntry KC_ALIGN(8);

/* ── Three-tier bloom structure ─────────────────────────── */
typedef struct {
    u8    *bits;         /* bit array */
    u64    n_bits;       /* total bits */
    u64    n_elements;   /* inserted elements */
    int    n_hashes;     /* number of hash functions */
    double fpr;          /* target false positive rate */
} BloomFilter;

typedef struct {
    BloomFilter l1[BLOOM_SUBFILTERS];  /* Level 1 — per first-byte */
    BloomFilter l2[BLOOM_SUBFILTERS];  /* Level 2 */
    BloomFilter l3[BLOOM_SUBFILTERS];  /* Level 3 */
    BPEntry    *bp_table;              /* exact bP lookup table */
    u64         bp_size;               /* number of bP entries */
    u64         M;                     /* baby step count */
    int         k_factor;              /* k-factor scaling */
} BSGSBloom;

/* ── BSGS configuration (v2) ────────────────────────────── */
typedef struct {
    /* Core params */
    int          table_bits;       /* m = 2^table_bits */
    u64          M;                /* baby step count = 2^table_bits */
    int          k_factor;         /* RAM multiplier: N = M * k (default 1) */
    Scalar       range_start;
    Scalar       range_end;
    int          threads;
    BSGSSubmode  submode;          /* sequential/backward/random/dance/middleout */

    /* Engine selection */
    bool         use_cyclone;
    bool         use_avx512;

    /* Files */
    char        *address_file;
    char        *output_file;
    char        *deep_file;        /* range input file  (default: deep.txt)    */
    char        *checked_file;     /* progress tracking (default: checked-deep.txt) */
    bool         save_files;       /* -S: persist bloom/bP to disk             */
    bool         skip_checksums;   /* -6: skip XXH3 verification (fast start)  */

    /* WIF mask */
    bool         use_wif_mask;
    char         wif_mask[60];     /* e.g. KwDiBf89QgGbjEhKnhXJuH___ */

    /* Stats */
    int          stats_interval;   /* seconds between status output (-s N) */
    bool         quiet;

    /* Mode flags */
    bool         random_mode;      /* -R: randomize starting giant step */
    u64          n_targets;        /* number of public keys being hunted */
} BSGSConfig;

/* ── Public key target ──────────────────────────────────── */
typedef struct {
    Point  pt;
    u8     hash160[20];
    char   address[64];
    bool   compressed;
} BSGSTarget;

/* ── Global BSGS state ──────────────────────────────────── */
typedef struct {
    BSGSBloom    bloom;
    BSGSTarget  *targets;
    size_t       n_targets;
    BSGSConfig   cfg;
} BSGSState;

/* ── Statistics ──────────────────────────────────────────── */
typedef struct {
    u64    baby_computed;
    u64    giant_steps;
    u64    bloom_l1_hits;
    u64    bloom_l2_hits;
    u64    bloom_l3_hits;
    u64    exact_matches;
    u64    keys_found;
    double elapsed_sec;
    double tkeys_per_sec;   /* Tkeys/s */
} BSGSStats;

extern BSGSStats     g_bsgs_stats;
extern BSGSState     g_bsgs_state;

/* ── API ─────────────────────────────────────────────────── */

/* Init / free */
int  bsgs_init(BSGSConfig *cfg);
void bsgs_free(void);

/* Load targets from file */
int  bsgs_load_targets(const char *path, BSGSTarget **targets, size_t *n);
void bsgs_targets_free(BSGSTarget *targets, size_t n);

/* Bloom / bP table management */
int  bsgs_build_bloom(BSGSBloom *bloom, const BSGSConfig *cfg,
                      const BSGSTarget *targets, size_t n_targets);
void bsgs_bloom_free(BSGSBloom *bloom);

/* Disk persistence */
int  bsgs_save_bloom(const BSGSBloom *bloom, const BSGSConfig *cfg);
int  bsgs_load_bloom(BSGSBloom *bloom, const BSGSConfig *cfg);
bool bsgs_files_exist(const BSGSConfig *cfg);

/* Three-tier lookup — returns baby_index or -1 */
i64  bsgs_bloom_lookup(const BSGSBloom *bloom, const u8 *hash160);
i64  bsgs_bp_exact_lookup(const BSGSBloom *bloom, u32 x_low);

/* Search dispatchers */
int  bsgs_search(BSGSState *state);
int  bsgs_search_sequential(BSGSState *state);
int  bsgs_search_backward(BSGSState *state);
int  bsgs_search_random(BSGSState *state);
int  bsgs_search_dance(BSGSState *state);
int  bsgs_search_middleout(BSGSState *state);
int  bsgs_search_range_file(BSGSState *state);  /* uses deep.txt */

/* Per-thread worker (internal) */
void *bsgs_worker_thread(void *arg);

/* Grouped batch baby-step generation (CPU_GRP_SIZE=1024) */
void bsgs_generate_baby_batch(BSGSBloom *bloom, u64 start, u64 count,
                               const BSGSConfig *cfg);

/* AVX-512 batch giant-step advance */
#ifdef HAVE_AVX512
void bsgs_avx512_giant_advance(CyclonePoint *pts, size_t n,
                                const CyclonePoint *step);
void bsgs_avx512_hash160_x16(const u8 pubkeys[16][33],
                               u8 hash160s[16][20]);
#endif

/* Stats */
void bsgs_stats_reset(BSGSStats *s);
void bsgs_stats_print(const BSGSStats *s);
void bsgs_stats_update_speed(BSGSStats *s);

#endif /* BSGS_H */
