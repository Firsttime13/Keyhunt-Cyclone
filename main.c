/*============================================================
 * Keyhunt-Cyclone — src/main.c  (v2 — 2025)
 *
 * New flags vs v1:
 *  -b BIT_RANGE   : bit range shorthand (65 → start=2^64, end=2^65-1)
 *  -k K_FACTOR    : RAM scaling for bloom (N = M * k)
 *  -w WIF_MASK    : partial WIF key search
 *  -D FILE        : range input file (deep.txt)
 *  -S             : save bloom/bP tables to disk
 *  -6             : skip XXH3 checksum verification
 *  -R             : random giant step ordering
 *  -s N           : stats every N seconds
 *  --submode M    : sequential|backward|both|random|dance|middleout
 *  --endo         : GLV endomorphism (warning: NOT compatible with BSGS)
 *  --no-compress  : uncompressed public keys
 *  --addr-type T  : p2pkh|p2sh|bech32
 *============================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

#include "keyhunt.h"

/* ── Globals ─────────────────────────────────────────────── */
AppConfig      g_cfg;
AddressFilter  g_filter;
CPUFeatures    g_cpu;
volatile bool  g_running      = true;
volatile u64   g_keys_found   = 0;
volatile u64   g_keys_checked = 0;
volatile u64   g_giant_steps  = 0;

/* ── Signal handler ──────────────────────────────────────── */
static void sig_handler(int sig) {
    (void)sig;
    g_running = false;
    fprintf(stderr, "\n" ANSI_YELLOW "[SIGNAL] Stopping gracefully..." ANSI_RESET "\n");
}

/* ── Long options ────────────────────────────────────────── */
static struct option long_opts[] = {
    /* Engine */
    {"cyclone",      no_argument,       0, 1001},
    {"avx512",       no_argument,       0, 1002},
    {"filter",       required_argument, 0, 1003},
    /* BSGS */
    {"submode",      required_argument, 0, 1004},
    {"endo",         no_argument,       0, 1005},
    /* Kangaroo */
    {"kangaroo-dp",  required_argument, 0, 1006},
    /* Address */
    {"addr-type",    required_argument, 0, 1007},
    {"prefix",       required_argument, 0, 1008},
    /* Misc */
    {"max",          required_argument, 0, 1009},
    {"no-compress",  no_argument,       0, 1010},
    {"batch",        required_argument, 0, 1011},
    {0, 0, 0, 0}
};

/* ── Usage ───────────────────────────────────────────────── */
static void print_usage(const char *prog) {
    printf(
        "\n"
        ANSI_CYAN
        "  Keyhunt-Cyclone v" KC_VERSION_STR "\n"
        "  High-performance secp256k1 private key search\n"
        "  EPYC 7773X / Threadripper 7000 optimized\n"
        ANSI_RESET "\n"
        "Usage: %s -m MODE [options]\n\n"

        "Modes (-m):\n"
        "  address    Sequential/random P2PKH/P2SH/bech32 search\n"
        "  bsgs       Baby-Step Giant-Step (most efficient)\n"
        "  xpoint     Search by EC x-coordinate\n"
        "  rmd        Search by RIPEMD-160 (~2x faster than address)\n"
        "  vanity     Vanity address prefix\n"
        "  kangaroo   Pollard's Lambda wild kangaroo\n"
        "  wif        WIF mask partial key search\n\n"

        "Core options:\n"
        "  -m MODE          Search mode (required)\n"
        "  -f FILE          Address / pubkey / hash160 file\n"
        "  -r START:END     Key range (hex)\n"
        "  -b BITS          Bit range: 65 → [2^64, 2^65) (BSGS default)\n"
        "  -n N             Baby step count (alternative to -b)\n"
        "  -k K             k-factor: N = 2^b * k  (RAM scaling, default 1)\n"
        "  -t THREADS       Thread count (default: all cores)\n"
        "  -o FILE          Output found keys\n\n"

        "BSGS options:\n"
        "  --submode M      sequential(default)|backward|both|random|dance|middleout\n"
        "  -R               Random giant step start\n"
        "  -S               Save bloom/bP tables to disk (fast restart)\n"
        "  -6               Skip XXH3 checksum verification\n"
        "  -D FILE          Range file (default: deep.txt)\n"
        "  -s N             Stats output every N seconds (default: 10)\n"
        "  -w WIFMASK       WIF mask search: KwDiBf89QgGb______\n\n"

        "Engine options:\n"
        "  --cyclone        Enable Cyclone EC Montgomery backend\n"
        "  --avx512         Force AVX-512 (auto-detected)\n"
        "  --endo           GLV endomorphism (NOT with BSGS!)\n"
        "  --filter TYPE    bfuse8 | bfuse16 | bloom | none\n"
        "  --addr-type T    p2pkh(default) | p2sh | bech32\n"
        "  --no-compress    Use uncompressed public keys\n"
        "  --batch N        Point batch size (default 1024)\n\n"

        "Other:\n"
        "  --prefix P       Vanity address prefix\n"
        "  --max N          Stop after N found keys\n"
        "  -q               Quiet mode (no thread noise)\n"
        "  -v               Verbose\n"
        "  -h               This help\n\n"

        "Examples:\n"
        "  # BSGS with Cyclone EC, 128 threads, bit-range 65, save tables\n"
        "  %s -m bsgs -f addr.txt -b 65 -t 128 --cyclone -S -s 5\n\n"
        "  # BSGS random mode, k-factor 4 (4x RAM for 4x speed)\n"
        "  %s -m bsgs -f addr.txt -b 65 -k 4 -R --cyclone\n\n"
        "  # BSGS from range file (deep.txt) with checkpoint\n"
        "  %s -m bsgs -f addr.txt -b 65 -D deep.txt --cyclone -S\n\n"
        "  # Kangaroo on narrow range\n"
        "  %s -m kangaroo -f addr.txt -r 1000000:2000000 --cyclone\n\n"
        "  # RMD mode (2x faster than address mode)\n"
        "  %s -m rmd -f hashes.txt -r 1:FFFFFFFFFF -t 128\n\n",
        prog, prog, prog, prog, prog, prog
    );
}

/* ── Parse bit range shorthand ───────────────────────────── */
static void parse_bit_range(int bits, Scalar *start, Scalar *end) {
    /* start = 2^(bits-1), end = 2^bits - 1 */
    memset(start->d, 0, 32);
    memset(end->d,   0, 32);
    if (bits <= 0 || bits > 256) return;

    int word = (bits - 1) / 64;
    int bit  = (bits - 1) % 64;
    start->d[word] = 1ULL << bit;

    /* end = 2^bits - 1 */
    int eword = bits / 64;
    int ebit  = bits % 64;
    if (ebit == 0) {
        /* all 1s in words 0..eword-1 */
        for (int i = 0; i < eword && i < 4; i++) end->d[i] = 0xFFFFFFFFFFFFFFFFULL;
    } else {
        for (int i = 0; i < eword && i < 4; i++) end->d[i] = 0xFFFFFFFFFFFFFFFFULL;
        if (eword < 4) end->d[eword] = (1ULL << ebit) - 1;
    }
}

/* ── Parse arguments ─────────────────────────────────────── */
static int parse_args(int argc, char **argv, AppConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    /* Defaults */
    cfg->mode           = MODE_UNKNOWN;
    cfg->addr_type      = ADDR_P2PKH;
    cfg->threads        = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (cfg->threads > KC_MAX_THREADS) cfg->threads = KC_MAX_THREADS;
    cfg->bsgs_bits      = BSGS_DEFAULT_BITS;
    cfg->k_factor       = 1;
    cfg->bsgs_submode   = BSGS_SUBMODE_SEQUENTIAL;
    cfg->kang_dp_bits   = 20;
    cfg->kang_n_tame    = 64;
    cfg->kang_n_wild    = 64;
    cfg->batch_size     = CPU_GRP_SIZE;
    cfg->filter_type    = FILTER_TYPE_NONE;
    cfg->stats_interval = KC_STATS_INTERVAL_SEC;
    cfg->compressed     = true;

    int opt, idx = 0;
    while ((opt = getopt_long(argc, argv, "m:f:r:b:n:k:t:o:w:D:s:RSq6vh",
                              long_opts, &idx)) != -1) {
        switch (opt) {
        case 'm':
            if      (!strcmp(optarg,"address"))   cfg->mode = MODE_ADDRESS;
            else if (!strcmp(optarg,"bsgs"))      cfg->mode = MODE_BSGS;
            else if (!strcmp(optarg,"xpoint"))    cfg->mode = MODE_XPOINT;
            else if (!strcmp(optarg,"rmd"))       cfg->mode = MODE_RMD;
            else if (!strcmp(optarg,"vanity"))    cfg->mode = MODE_VANITY;
            else if (!strcmp(optarg,"kangaroo"))  cfg->mode = MODE_KANGAROO;
            else if (!strcmp(optarg,"wif"))       cfg->mode = MODE_WIF_MASK;
            else { KC_ERR("Unknown mode: %s", optarg); return -1; }
            break;
        case 'f': cfg->address_file = optarg; break;
        case 'r': strncpy(cfg->range_str, optarg, 129); break;
        case 'b':
            cfg->bit_range = atoi(optarg);
            if (cfg->bit_range >= 1 && cfg->bit_range <= 256)
                parse_bit_range(cfg->bit_range, &cfg->range_start, &cfg->range_end);
            else { KC_ERR("Bit range must be 1..256"); return -1; }
            break;
        case 'n': {
            /* -n N → treat as M (baby step count), set bits = log2(N) */
            u64 n = strtoull(optarg, NULL, 10);
            cfg->bsgs_bits = (int)ceil(log2((double)n));
            if (cfg->bsgs_bits < BSGS_MIN_BITS) cfg->bsgs_bits = BSGS_MIN_BITS;
            if (cfg->bsgs_bits > BSGS_MAX_BITS) cfg->bsgs_bits = BSGS_MAX_BITS;
            break;
        }
        case 'k':
            cfg->k_factor = atoi(optarg);
            if (cfg->k_factor < 1) cfg->k_factor = 1;
            break;
        case 't':
            cfg->threads = atoi(optarg);
            if (cfg->threads < 1) cfg->threads = 1;
            if (cfg->threads > KC_MAX_THREADS) cfg->threads = KC_MAX_THREADS;
            break;
        case 'o': cfg->output_file = optarg; break;
        case 'w':
            strncpy(cfg->wif_mask, optarg, 59);
            cfg->use_wif_mask = true;
            break;
        case 'D': cfg->deep_file = optarg; break;
        case 's': cfg->stats_interval = atoi(optarg); break;
        case 'R': cfg->bsgs_random = true; break;
        case 'S': cfg->bsgs_save   = true; break;
        case '6': cfg->bsgs_skip_cksum = true; break;
        case 'q': cfg->quiet  = true; break;
        case 'v': cfg->verbose = true; break;
        case 'h': print_usage(argv[0]); exit(0);

        /* Long options */
        case 1001: cfg->use_cyclone = true; break;
        case 1002: cfg->use_avx512  = true; break;
        case 1003:
            if      (!strcmp(optarg,"bfuse8"))  cfg->filter_type = FILTER_TYPE_BFUSE8;
            else if (!strcmp(optarg,"bfuse16")) cfg->filter_type = FILTER_TYPE_BFUSE16;
            else if (!strcmp(optarg,"bloom"))   cfg->filter_type = FILTER_TYPE_BLOOM;
            else if (!strcmp(optarg,"none"))    cfg->filter_type = FILTER_TYPE_NONE;
            break;
        case 1004:
            if      (!strcmp(optarg,"sequential"))  cfg->bsgs_submode = BSGS_SUBMODE_SEQUENTIAL;
            else if (!strcmp(optarg,"backward"))    cfg->bsgs_submode = BSGS_SUBMODE_BACKWARD;
            else if (!strcmp(optarg,"both"))        cfg->bsgs_submode = BSGS_SUBMODE_BOTH;
            else if (!strcmp(optarg,"random"))      cfg->bsgs_submode = BSGS_SUBMODE_RANDOM;
            else if (!strcmp(optarg,"dance"))       cfg->bsgs_submode = BSGS_SUBMODE_DANCE;
            else if (!strcmp(optarg,"middleout"))   cfg->bsgs_submode = BSGS_SUBMODE_MIDDLEOUT;
            else { KC_ERR("Unknown submode: %s", optarg); return -1; }
            break;
        case 1005:
            cfg->endomorphism = true;
            KC_WARN("GLV endomorphism enabled. WARNING: NOT compatible with BSGS mode!");
            break;
        case 1006: cfg->kang_dp_bits = atoi(optarg); break;
        case 1007:
            if      (!strcmp(optarg,"p2pkh"))  cfg->addr_type = ADDR_P2PKH;
            else if (!strcmp(optarg,"p2sh"))   cfg->addr_type = ADDR_P2SH;
            else if (!strcmp(optarg,"bech32")) cfg->addr_type = ADDR_BECH32;
            break;
        case 1008: strncpy(cfg->vanity_prefix, optarg, 39); break;
        case 1009: cfg->max_found = strtoull(optarg, NULL, 10); break;
        case 1010: cfg->compressed = false; break;
        case 1011: cfg->batch_size = atoi(optarg); break;
        default: return -1;
        }
    }

    /* Validation */
    if (cfg->mode == MODE_UNKNOWN) {
        KC_ERR("No mode specified. Use -m MODE. Try -h for help.");
        return -1;
    }
    if (!cfg->address_file && cfg->mode != MODE_VANITY) {
        KC_ERR("No address file. Use -f FILE.");
        return -1;
    }
    if (cfg->mode == MODE_BSGS && cfg->endomorphism) {
        KC_ERR("BSGS and GLV endomorphism are NOT compatible. Remove --endo.");
        return -1;
    }

    /* Parse hex range (overrides -b if both given) */
    if (cfg->range_str[0] && !cfg->bit_range) {
        char *colon = strchr(cfg->range_str, ':');
        if (!colon) { KC_ERR("Range must be START:END"); return -1; }
        *colon = '\0';
        u8 tmp[32] = {0};
        char padded[65] = {0};
        size_t slen;

        slen = strlen(cfg->range_str);
        memset(padded,'0',64);
        memcpy(padded+64-slen, cfg->range_str, slen);
        hex2bin(padded, tmp, 32);
        scalar_from_bytes(&cfg->range_start, tmp);

        slen = strlen(colon+1);
        memset(padded,'0',64);
        memcpy(padded+64-slen, colon+1, slen);
        hex2bin(padded, tmp, 32);
        scalar_from_bytes(&cfg->range_end, tmp);
        *colon = ':';
    }

    /* Auto-detect AVX-512 */
    if (g_cpu.avx512f && !cfg->use_avx512) {
        cfg->use_avx512 = true;
        if (cfg->verbose) KC_LOG("AVX-512 auto-enabled (znver%d)", g_cpu.znver);
    }

    /* Warn if range unset */
    if (cfg->mode == MODE_BSGS) {
        bool no_range = !cfg->bit_range && !cfg->range_str[0];
        if (no_range) {
            KC_WARN("No range specified for BSGS. Defaulting to bit 65.");
            parse_bit_range(65, &cfg->range_start, &cfg->range_end);
            cfg->bit_range = 65;
        }
    }

    return 0;
}

/* ── Banner ──────────────────────────────────────────────── */
static void print_banner(const AppConfig *cfg) {
    static const char *mode_names[] = {
        "unknown","address","BSGS","xpoint","rmd160",
        "vanity","kangaroo","minikeys","WIF-mask"
    };
    static const char *submode_names[] = {
        "sequential","backward","both","random","dance","middleout"
    };

    printf("\n");
    printf(ANSI_CYAN "╔══════════════════════════════════════════════╗\n" ANSI_RESET);
    printf(ANSI_CYAN "║  " ANSI_YELLOW "Keyhunt-Cyclone v%-27s" ANSI_CYAN "║\n" ANSI_RESET,
           KC_VERSION_STR "  ");
    printf(ANSI_CYAN "╚══════════════════════════════════════════════╝\n" ANSI_RESET);
    printf("\n");
    printf("  CPU arch:  %s (znver%d)\n",
           g_cpu.znver==4 ? "AMD EPYC Genoa/Threadripper 7000" :
           g_cpu.znver==3 ? "AMD EPYC Milan/Ryzen 5000" :
           g_cpu.znver==2 ? "AMD EPYC Rome/Ryzen 3000" : "x86-64",
           g_cpu.znver);
    printf("  AVX-512:   %s%s" ANSI_RESET "  IFMA52: %s%s" ANSI_RESET
           "  VAES: %s%s" ANSI_RESET "\n",
           g_cpu.avx512f   ? ANSI_GREEN : ANSI_RED,
           g_cpu.avx512f   ? "YES" : "NO",
           g_cpu.avx512ifma? ANSI_GREEN : ANSI_RED,
           g_cpu.avx512ifma? "YES" : "NO",
           g_cpu.vaes      ? ANSI_GREEN : ANSI_RED,
           g_cpu.vaes      ? "YES" : "NO");
    printf("  Threads:   %d\n", cfg->threads);
    printf("  Mode:      %s", mode_names[cfg->mode]);
    if (cfg->mode == MODE_BSGS)
        printf("  [%s]", submode_names[cfg->bsgs_submode]);
    printf("\n");
    printf("  Cyclone:   %s%s" ANSI_RESET "\n",
           cfg->use_cyclone ? ANSI_GREEN : "", cfg->use_cyclone ? "YES" : "no");
    if (cfg->bit_range)
        printf("  Bit range: %d  [2^%d .. 2^%d)\n",
               cfg->bit_range, cfg->bit_range-1, cfg->bit_range);
    else if (cfg->range_str[0])
        printf("  Range:     %s\n", cfg->range_str);
    if (cfg->mode == MODE_BSGS) {
        u64 M = 1ULL << cfg->bsgs_bits;
        printf("  M (baby):  %llu  k-factor: %d  N=%llu\n",
               (unsigned long long)M, cfg->k_factor,
               (unsigned long long)(M * (u64)cfg->k_factor));
        if (cfg->bsgs_save) printf("  Tables:    will be saved to disk (-S)\n");
    }
    if (cfg->use_wif_mask)
        printf("  WIF mask:  %s\n", cfg->wif_mask);
    printf("\n");
}

/* ── Status thread ───────────────────────────────────────── */
void *status_thread_fn(void *arg) {
    const AppConfig *cfg = (const AppConfig *)arg;
    time_t start = time(NULL);
    u64    last_checked = 0;

    while (g_running) {
        sleep((unsigned)cfg->stats_interval);
        u64 now    = g_keys_checked;
        u64 found  = g_keys_found;
        double el  = difftime(time(NULL), start);
        double rate = el > 0 ? (double)now / el : 0;
        double trate = rate / 1e12;

        if (cfg->mode == MODE_BSGS) {
            printf(ANSI_CYAN "\r[%.0fs] giant_steps=%-10llu checked=%-14llu "
                   "found=%llu  %.3f Tkeys/s   " ANSI_RESET,
                   el,
                   (unsigned long long)g_giant_steps,
                   (unsigned long long)now,
                   (unsigned long long)found,
                   trate);
        } else {
            printf(ANSI_CYAN "\r[%.0fs] checked=%-14llu found=%llu  %.3f Mkeys/s   "
                   ANSI_RESET,
                   el,
                   (unsigned long long)now,
                   (unsigned long long)found,
                   rate / 1e6);
        }
        fflush(stdout);
        last_checked = now;
    }
    printf("\n");
    return NULL;
}

/* ── Main ────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Detect CPU first */
    cpu_detect(&g_cpu);

    if (argc < 2) { print_usage(argv[0]); return 1; }

    if (parse_args(argc, argv, &g_cfg) != 0) return 1;

    print_banner(&g_cfg);

    /* Init subsystems */
    secp256k1_build_gtable();
    if (g_cfg.use_cyclone) {
        cyclone_init();
        cyclone_build_G_table();
    }

    /* Load address filter if requested */
    if (g_cfg.address_file && g_cfg.filter_type != FILTER_TYPE_NONE) {
        KC_LOG("Building %s filter from %s...",
               g_cfg.filter_type == FILTER_TYPE_BFUSE8  ? "BFuse8"  :
               g_cfg.filter_type == FILTER_TYPE_BFUSE16 ? "BFuse16" : "Bloom",
               g_cfg.address_file);
        if (filter_build_from_file(&g_filter, g_cfg.address_file,
                                   g_cfg.filter_type) != 0) {
            KC_ERR("Filter build failed");
            return 1;
        }
        filter_print_stats(&g_filter);
    }

    /* Start status thread */
    pthread_t status_tid;
    bool status_running = false;
    if (!g_cfg.quiet && g_cfg.stats_interval > 0) {
        pthread_create(&status_tid, NULL, status_thread_fn, &g_cfg);
        status_running = true;
    }

    /* Dispatch mode */
    int ret = 0;
    switch (g_cfg.mode) {
    case MODE_ADDRESS:   ret = run_address_mode(&g_cfg);   break;
    case MODE_BSGS:      ret = run_bsgs_mode(&g_cfg);      break;
    case MODE_XPOINT:    ret = run_xpoint_mode(&g_cfg);    break;
    case MODE_RMD:       ret = run_rmd_mode(&g_cfg);       break;
    case MODE_VANITY:    ret = run_vanity_mode(&g_cfg);    break;
    case MODE_KANGAROO:  ret = run_kangaroo_mode(&g_cfg);  break;
    case MODE_WIF_MASK:  ret = run_wif_mask_mode(&g_cfg);  break;
    default:
        KC_ERR("Unknown mode");
        ret = -1;
    }

    g_running = false;
    if (status_running) pthread_join(status_tid, NULL);

    /* Final summary */
    printf("\n");
    KC_OK("Done. Keys found: %llu  Total checked: %llu",
          (unsigned long long)g_keys_found,
          (unsigned long long)g_keys_checked);

    app_cleanup();
    return ret;
}
