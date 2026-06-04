/*============================================================
 * Keyhunt-Cyclone — tools/gen_table.c  (v2 — 2025)
 *
 * Standalone utility: pre-computes the BSGS baby-step bloom
 * and bP table and saves them to disk.  Run once, then use
 * -S -6 on subsequent keyhunt-cyclone invocations to skip
 * the baby-step generation phase entirely.
 *
 * Usage:
 *   ./gen_table -b BITS -t THREADS [-k K_FACTOR] [-o OUTDIR]
 *
 * Output files (in current directory unless -o given):
 *   keyhunt_bsgs_4_<M>.blm   — L1 bloom filter
 *   keyhunt_bsgs_6_<M>.blm   — L2 bloom filter
 *   keyhunt_bsgs_7_<M>.blm   — L3 bloom filter
 *   keyhunt_bsgs_2_<N>.tbl   — sorted bP exact table
 *============================================================*/

#include "keyhunt.h"
#include <getopt.h>
#include <time.h>

/* Globals required by keyhunt.h / secp256k1.h */
AppConfig      g_cfg;
AddressFilter  g_filter;
CPUFeatures    g_cpu;
volatile bool  g_running      = true;
volatile u64   g_keys_found   = 0;
volatile u64   g_keys_checked = 0;
volatile u64   g_giant_steps  = 0;

static void usage(const char *p) {
    printf("Usage: %s -b BITS [-t THREADS] [-k K] [-o DIR]\n\n"
           "  -b BITS     Baby-step table bits (18..28, default 24)\n"
           "  -t THREADS  Thread count (default: all cores)\n"
           "  -k K        k-factor (N = 2^b * k, default 1)\n"
           "  -o DIR      Output directory (default: current dir)\n\n"
           "Example (EPYC 7773X, bit-65 hunt):\n"
           "  ./gen_table -b 24 -t 128 -k 4\n"
           "  # generates ~512 MB bloom + ~32 MB bP table\n"
           "  # subsequent runs: ./keyhunt-cyclone -m bsgs ... -S -6\n\n",
           p);
}

int main(int argc, char **argv) {
    cpu_detect(&g_cpu);

    int bits    = BSGS_DEFAULT_BITS;
    int threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    int kfact   = 1;
    char *outdir = ".";

    int opt;
    while ((opt = getopt(argc, argv, "b:t:k:o:h")) != -1) {
        switch (opt) {
        case 'b': bits    = atoi(optarg); break;
        case 't': threads = atoi(optarg); break;
        case 'k': kfact   = atoi(optarg); break;
        case 'o': outdir  = optarg;        break;
        case 'h': usage(argv[0]);          return 0;
        default:  usage(argv[0]);          return 1;
        }
    }

    if (bits < BSGS_MIN_BITS || bits > BSGS_MAX_BITS) {
        fprintf(stderr, "ERROR: bits must be %d..%d\n",
                BSGS_MIN_BITS, BSGS_MAX_BITS);
        return 1;
    }
    if (threads < 1) threads = 1;
    if (kfact   < 1) kfact   = 1;

    u64 M = (1ULL << bits) * (u64)kfact;

    /* Memory estimate */
    char mem_est[32];
    estimate_bloom_memory(M, 1, mem_est, sizeof(mem_est));

    printf("\n");
    printf("╔═══════════════════════════════════════════╗\n");
    printf("║  Keyhunt-Cyclone — gen_table  v%s        ║\n", KC_VERSION_STR);
    printf("╚═══════════════════════════════════════════╝\n\n");
    printf("  bits    = %d\n", bits);
    printf("  k       = %d\n", kfact);
    printf("  M       = %llu  (~%s RAM)\n",
           (unsigned long long)M, mem_est);
    printf("  threads = %d\n", threads);
    printf("  outdir  = %s\n\n", outdir);

    /* Build generator tables */
    secp256k1_build_gtable();
    cyclone_init();
    cyclone_build_G_table();

    /* Configure */
    BSGSConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.table_bits     = bits;
    cfg.M              = M;
    cfg.k_factor       = kfact;
    cfg.threads        = threads;
    cfg.use_cyclone    = (g_cpu.avx512f != 0);
    cfg.use_avx512     = (g_cpu.avx512f != 0);
    cfg.save_files     = true;
    cfg.skip_checksums = false;
    cfg.stats_interval = 30;
    scalar_set_u64(&cfg.range_start, 0);
    memset(cfg.range_end.d, 0xFF, 32);

    bsgs_init(&cfg);

    /* Build bloom / bP tables */
    time_t t0 = time(NULL);
    KC_LOG("Starting baby-step generation...");

    int ret = bsgs_build_bloom(&g_bsgs_state.bloom, &cfg, NULL, 0);
    if (ret != 0) {
        KC_ERR("Baby-step generation failed (out of memory?)");
        return 1;
    }

    double elapsed = difftime(time(NULL), t0);
    KC_LOG("Baby steps completed in %.1f seconds", elapsed);

    /* Save to disk */
    KC_LOG("Saving tables to %s/ ...", outdir);

    /* Change to output directory */
    if (chdir(outdir) != 0) {
        KC_ERR("Cannot chdir to %s", outdir);
        return 1;
    }

    ret = bsgs_save_bloom(&g_bsgs_state.bloom, &cfg);
    if (ret != 0) {
        KC_ERR("Failed to save tables");
        return 1;
    }

    /* Print checksums for verification */
    char path[256];
    snprintf(path, 256, BSGS_FILE_BLM1_FMT, (unsigned long long)M);
    u64 cksum = xxh3_file_checksum(path);
    KC_OK("Bloom L1 saved: %s  checksum=0x%016llX", path,
          (unsigned long long)cksum);

    snprintf(path, 256, BSGS_FILE_TBL_FMT,
             (unsigned long long)(M / BLOOM_L3_DIVISOR + 1));
    cksum = xxh3_file_checksum(path);
    KC_OK("bP table saved: %s  checksum=0x%016llX", path,
          (unsigned long long)cksum);

    printf("\n");
    KC_OK("Tables ready. Use with keyhunt-cyclone:");
    printf("  ./keyhunt-cyclone -m bsgs -f addresses.txt"
           " -b %d -k %d -t %d --cyclone -S -6 -s 5\n\n",
           bits, kfact, threads);

    bsgs_bloom_free(&g_bsgs_state.bloom);
    return 0;
}
