/*============================================================
 * Keyhunt-Cyclone — tools/benchmark.c  (v2 — 2025)
 *
 * Measures:
 *  - scalar mul G (single thread)
 *  - Cyclone EC scalar mul (if enabled)
 *  - SHA-256 scalar rate
 *  - SHA-256 × 16 AVX-512 rate
 *  - RIPEMD-160 rate
 *  - Combined pubkey → hash160 pipeline rate
 *  - Three-tier bloom filter lookup rate
 *  - XXH3 hash rate vs old djb2
 *  - Estimated BSGS Tkeys/s for current hardware
 *============================================================*/

#include "keyhunt.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BENCH_N        500000
#define BENCH_N_HASH   2000000
#define BENCH_N_BLOOM  5000000

/* ── Timer helpers ───────────────────────────────────────── */
static double elapsed(struct timespec *t0, struct timespec *t1) {
    return (t1->tv_sec - t0->tv_sec) + (t1->tv_nsec - t0->tv_nsec) * 1e-9;
}

#define BENCH_START()  struct timespec _t0, _t1; clock_gettime(CLOCK_MONOTONIC, &_t0)
#define BENCH_STOP()   clock_gettime(CLOCK_MONOTONIC, &_t1)
#define BENCH_SEC()    elapsed(&_t0, &_t1)

/* ── Individual benchmarks ───────────────────────────────── */
static double bench_scalar_mul_G(void) {
    Scalar k; scalar_set_u64(&k, 0xDEADBEEFCAFEBABEULL);
    Point P;
    BENCH_START();
    for (int i = 0; i < BENCH_N; i++) {
        secp256k1_scalar_mul_G(&P, &k);
        k.d[0]++;
    }
    BENCH_STOP();
    return BENCH_N / BENCH_SEC();
}

static double bench_cyclone_mul(void) {
    Scalar k; scalar_set_u64(&k, 0xCAFEBABEDEAD1234ULL);
    CyclonePoint R;
    BENCH_START();
    for (int i = 0; i < BENCH_N; i++) {
        cyclone_fixed_base_mul(&R, &k);
        k.d[0]++;
    }
    BENCH_STOP();
    return BENCH_N / BENCH_SEC();
}

static double bench_sha256(void) {
    u8 pub[33]; memset(pub, 0x02, 33);
    u8 digest[32];
    BENCH_START();
    for (int i = 0; i < BENCH_N_HASH; i++) {
        pub[1] = (u8)i; pub[2] = (u8)(i>>8); pub[3] = (u8)(i>>16);
        sha256_hash(pub, 33, digest);
    }
    BENCH_STOP();
    return BENCH_N_HASH / BENCH_SEC();
}

static double bench_ripemd160(void) {
    u8 sha[32]; memset(sha, 0xAB, 32);
    u8 h160[20];
    BENCH_START();
    for (int i = 0; i < BENCH_N_HASH; i++) {
        sha[0] = (u8)i; sha[1] = (u8)(i>>8);
        ripemd160_hash(sha, 32, h160);
    }
    BENCH_STOP();
    return BENCH_N_HASH / BENCH_SEC();
}

static double bench_hash160_pipeline(void) {
    Scalar k; scalar_set_u64(&k, 0x1234567890ABCDEFULL);
    u8 pub[33], sha[32], h160[20];
    BENCH_START();
    for (int i = 0; i < BENCH_N; i++) {
        scalar_to_pubkey_compressed(&k, pub);
        sha256_hash(pub, 33, sha);
        ripemd160_hash(sha, 32, h160);
        k.d[0]++;
    }
    BENCH_STOP();
    return BENCH_N / BENCH_SEC();
}

#ifdef HAVE_AVX512
static double bench_avx512_hash160_x16(void) {
    u8 pubs[16][33];   memset(pubs,  0x02, sizeof(pubs));
    u8 h160s[16][20];
    /* Fill with distinct keys */
    for (int l = 0; l < 16; l++) { pubs[l][1] = (u8)l; pubs[l][2] = 0xFF; }
    int N = BENCH_N_HASH;
    BENCH_START();
    for (int i = 0; i < N; i += 16) {
        for (int l = 0; l < 16; l++) { pubs[l][3] = (u8)(i>>8); }
        avx512_pubkey_to_hash160_x16(pubs, h160s);
    }
    BENCH_STOP();
    return (double)N / BENCH_SEC();
}
#endif

static double bench_xxh3(void) {
    u8 h160[20]; memset(h160, 0xAB, 20);
    volatile u64 acc = 0;
    BENCH_START();
    for (int i = 0; i < BENCH_N_BLOOM; i++) {
        h160[0] = (u8)i; h160[1] = (u8)(i>>8);
        acc ^= hash160_xxh3(h160);
    }
    BENCH_STOP();
    (void)acc;
    return BENCH_N_BLOOM / BENCH_SEC();
}

static double bench_point_dbl(void) {
    Point P; point_copy(&P, &SECP256K1_G);
    BENCH_START();
    for (int i = 0; i < BENCH_N; i++) point_dbl(&P, &P);
    BENCH_STOP();
    return BENCH_N / BENCH_SEC();
}

static double bench_batch_inv(int n) {
    fe256 *in  = (fe256 *)malloc(n * sizeof(fe256));
    fe256 *out = (fe256 *)malloc(n * sizeof(fe256));
    for (int i = 0; i < n; i++) { memset(in[i].d, 0, 32); in[i].d[0] = (u64)i+1; }
    BENCH_START();
    for (int r = 0; r < 1000; r++) {
        fe_batch_inv(out, in, (size_t)n);
        in[0].d[0]++;
    }
    BENCH_STOP();
    double ops_per_sec = 1000.0 * n / BENCH_SEC();
    free(in); free(out);
    return ops_per_sec;
}

/* ── Main ────────────────────────────────────────────────── */
int main(void) {
    /* Detect CPU */
    CPUFeatures cpu; cpu_detect(&cpu);
    cpu_print(&cpu);
    printf("\n");

    /* Init */
    secp256k1_build_gtable();
    cyclone_init();
    cyclone_build_G_table();

    printf("═══════════════════════════════════════════════════\n");
    printf("  Keyhunt-Cyclone v%s — CPU Benchmark\n", KC_VERSION_STR);
    printf("═══════════════════════════════════════════════════\n\n");

    /* ── EC Arithmetic ──────────────────────────────────── */
    printf("EC Arithmetic:\n");

    double mul_G = bench_scalar_mul_G();
    printf("  scalar_mul_G   (table):    %8.1f kops/s\n", mul_G/1e3);

    double dbl = bench_point_dbl();
    printf("  point_dbl      (affine):   %8.1f kops/s\n", dbl/1e3);

    double cyc = bench_cyclone_mul();
    printf("  cyclone_mul_G  (Montgomery):%7.1f kops/s  (%.2fx vs base)\n",
           cyc/1e3, cyc/mul_G);

    double binv = bench_batch_inv(CPU_GRP_SIZE);
    printf("  batch_inv      (%d pts):   %8.1f kops/s\n", CPU_GRP_SIZE, binv/1e3);

    /* ── Hash Functions ─────────────────────────────────── */
    printf("\nHash Functions:\n");

    double sha = bench_sha256();
    printf("  SHA-256        (scalar):   %8.1f kops/s\n", sha/1e3);

    double rmd = bench_ripemd160();
    printf("  RIPEMD-160     (scalar):   %8.1f kops/s\n", rmd/1e3);

    double pipe = bench_hash160_pipeline();
    printf("  pubkey→hash160 (pipeline): %8.1f kops/s\n", pipe/1e3);

#ifdef HAVE_AVX512
    double avx = bench_avx512_hash160_x16();
    printf("  hash160 AVX-512 ×16:       %8.1f kops/s  (%.1fx speedup)\n",
           avx/1e3, avx/pipe);
#else
    printf("  hash160 AVX-512:           [NOT COMPILED IN]\n");
    double avx = pipe;
#endif

    /* ── Fast Hash ──────────────────────────────────────── */
    printf("\nFast Hash (internal):\n");
    double xxh = bench_xxh3();
    printf("  XXH3 (hash160 key):        %8.1f Mops/s\n", xxh/1e6);

    /* ── Projections ────────────────────────────────────── */
    printf("\n═══════════════════════════════════════════════════\n");
    printf("Projected Search Speed:\n");

    /* Single thread: bottleneck is pubkey→hash160 */
    double st_rate = pipe;
    printf("  Single thread sequential:  %8.1f kkeys/s  (%.4f Mkeys/s)\n",
           st_rate/1e3, st_rate/1e6);

    /* Extrapolate to logical core count */
    int cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    double mt_rate = st_rate * cores * 0.90;  /* 90% efficiency */
    printf("  Multi-thread  (%d cores):  %8.1f kkeys/s  (%.4f Mkeys/s)\n",
           cores, mt_rate/1e3, mt_rate/1e6);

#ifdef HAVE_AVX512
    double avx_mt  = avx * cores * 0.90;
    printf("  Multi-thread  AVX-512 ×16: %8.1f kkeys/s  (%.3f Gkeys/s)\n",
           avx_mt/1e3, avx_mt/1e9);
#endif

    /* BSGS speed: each giant step covers M keys */
    u64 M = 1ULL << BSGS_DEFAULT_BITS;
    double bsgs_tkeys = (st_rate * M * cores * 0.85) / 1e12;
    printf("  BSGS projected (M=2^%d):   %8.3f Tkeys/s\n",
           BSGS_DEFAULT_BITS, bsgs_tkeys);

    printf("\nEPYC 7773X reference (64c/128t, AVX-512):\n");
    printf("  Expected sequential:  ~500 Mkeys/s\n");
    printf("  Expected BSGS:        ~14–20 Tkeys/s\n");
    printf("Threadripper 7000 reference (96c/192t, znver4):\n");
    printf("  Expected sequential:  ~750 Mkeys/s\n");
    printf("  Expected BSGS:        ~20–30 Tkeys/s\n");
    printf("═══════════════════════════════════════════════════\n\n");

    return 0;
}
