#ifndef KEYHUNT_H
#define KEYHUNT_H

/*============================================================
 * Keyhunt-Cyclone — keyhunt.h  (v2 — 2025)
 *
 * Updates:
 *  - WIF mask mode (-w flag)
 *  - Range file (-D deep.txt) with checkpoint tracking
 *  - Stats interval (-s N) flag
 *  - -S save bloom/bP tables to disk
 *  - -6 skip checksum verification
 *  - -R random giant step mode
 *  - -k k-factor RAM scaling
 *  - -q quiet thread output
 *  - Bit range (-b) replaces -n for BSGS
 *  - All BSGS submodes exposed via --submode
 *  - AOCC/GCC 14 znver4 support in build flags
 *============================================================*/

#include "common.h"
#include "secp256k1.h"
#include "bsgs.h"
#include "cyclone.h"
#include "kangaroo.h"
#include "binary_fuse.h"
#include "avx512_ec.h"

/* ── Search modes ────────────────────────────────────────── */
typedef enum {
    MODE_UNKNOWN    = 0,
    MODE_ADDRESS    = 1,
    MODE_BSGS       = 2,
    MODE_XPOINT     = 3,
    MODE_RMD        = 4,   /* RIPEMD-160 direct (~2× faster than address) */
    MODE_VANITY     = 5,
    MODE_KANGAROO   = 6,
    MODE_MINIKEYS   = 7,
    MODE_WIF_MASK   = 8,   /* NEW: WIF partial key search */
} SearchMode;

typedef enum {
    ADDR_P2PKH  = 0,
    ADDR_P2SH   = 1,
    ADDR_BECH32 = 2,
} AddrType;

/* ── Full application config (v2) ───────────────────────── */
typedef struct {
    SearchMode   mode;
    AddrType     addr_type;

    /* Keyspace */
    Scalar       range_start;
    Scalar       range_end;
    char         range_str[130];
    int          bit_range;        /* -b: bit range (65 → 2^64:2^65-1) */

    /* Input / Output */
    char        *address_file;
    char        *output_file;
    char        *deep_file;        /* -D: range file (default deep.txt) */
    char        *checked_file;     /* progress checkpoint file */

    /* Engine */
    bool         use_cyclone;
    bool         use_avx512;
    FilterType   filter_type;

    /* Threading */
    int          threads;
    int          batch_size;       /* point batch size */

    /* BSGS */
    int          bsgs_bits;        /* -b: table bits 18..28 */
    int          k_factor;         /* -k: RAM scaling factor */
    BSGSSubmode  bsgs_submode;
    bool         bsgs_save;        /* -S: save bloom/bP files */
    bool         bsgs_skip_cksum;  /* -6: skip XXH3 verify */
    bool         bsgs_random;      /* -R: random giant step */

    /* WIF mask */
    char         wif_mask[60];     /* -w: e.g. KwDiBf89QgGb___... */
    bool         use_wif_mask;

    /* Kangaroo */
    int          kang_dp_bits;
    u64          kang_n_tame;
    u64          kang_n_wild;

    /* Vanity */
    char         vanity_prefix[40];

    /* Misc */
    bool         verbose;
    bool         quiet;
    int          stats_interval;   /* -s N: seconds between stats output */
    u64          max_found;
    bool         endomorphism;     /* --endo: GLV endomorphism (NOT with BSGS!) */
    bool         compressed;       /* default: true */
} AppConfig;

/* ── Globals ─────────────────────────────────────────────── */
extern AppConfig      g_cfg;
extern AddressFilter  g_filter;
extern CPUFeatures    g_cpu;
extern volatile bool  g_running;
extern volatile u64   g_keys_found;
extern volatile u64   g_keys_checked;
extern volatile u64   g_giant_steps;

/* ── Functions ───────────────────────────────────────────── */
int  app_init(AppConfig *cfg);
void app_run(AppConfig *cfg);
void app_cleanup(void);

/* Mode runners */
int  run_address_mode(const AppConfig *cfg);
int  run_bsgs_mode(const AppConfig *cfg);
int  run_xpoint_mode(const AppConfig *cfg);
int  run_rmd_mode(const AppConfig *cfg);
int  run_vanity_mode(const AppConfig *cfg);
int  run_kangaroo_mode(const AppConfig *cfg);
int  run_wif_mask_mode(const AppConfig *cfg);

/* Address utilities */
void hash160_to_p2pkh(const u8 *h160, char *out);
void hash160_to_p2sh(const u8 *h160, char *out);
void hash160_to_bech32(const u8 *h160, char *out);
void scalar_to_address(const Scalar *k, AddrType type,
                       bool compressed, char *addr, u8 *h160);
void scalar_to_wif(const Scalar *k, bool compressed, char *wif);
int  wif_to_scalar(const char *wif, Scalar *k, bool *compressed);

/* Base58 */
int  base58check_encode(const u8 *in, size_t len, char *out);
int  base58check_decode(const char *in, u8 *out, size_t *len);

/* Key reporting */
void report_found_key(const Scalar *k, const u8 *h160,
                      const char *addr, const AppConfig *cfg);

/* Range file support */
int  rangefile_load(const char *path, Scalar *starts, Scalar *ends,
                    size_t *count);
void rangefile_mark_done(const char *checked_path,
                         const Scalar *start, const Scalar *end);

/* Status thread */
void *status_thread_fn(void *arg);

/* WIF mask search */
bool wif_mask_match(const char *wif, const char *mask);
void wif_mask_generate_range(const char *mask, Scalar *lo, Scalar *hi);

/* Hash functions */
void sha256_hash(const u8 *msg,  size_t len, u8 digest[32]);
void sha256d_hash(const u8 *msg, size_t len, u8 digest[32]);
void ripemd160_hash(const u8 *msg, size_t len, u8 digest[20]);

/* XXH3 file checksum */
u64  xxh3_file_checksum(const char *path);
bool xxh3_verify_file(const char *path, u64 expected);

#endif /* KEYHUNT_H */
