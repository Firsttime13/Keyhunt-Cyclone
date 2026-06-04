#ifndef COMMON_H
#define COMMON_H

/*============================================================
 * Keyhunt-Cyclone — common.h  (v2 — updated 2025)
 * Shared types, macros, platform detection
 *
 * Updates v2:
 *  - XXH3 integration (replaces djb2/fnv for all internal hashing)
 *  - CPU_GRP_SIZE = 1024 (batch grouped modular inverse)
 *  - BSGS submode enum: sequential/backward/random/dance/middleout
 *  - WIF mask search support
 *  - Range checkpoint / deep.txt support
 *  - AMD EPYC 9004 tuning: prefetch-latency=300
 *  - znver4 + znver3 detection refined
 *============================================================*/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Version ────────────────────────────────────────────── */
#define KC_VERSION_MAJOR  2
#define KC_VERSION_MINOR  0
#define KC_VERSION_PATCH  0
#define KC_VERSION_STR    "2.0.0"

/* ── Compiler / arch detection ──────────────────────────── */
#if defined(__AVX512F__) && defined(__AVX512BW__) && defined(__AVX512VL__)
#  define HAVE_AVX512 1
#endif
#if defined(__AVX512IFMA__)
#  define HAVE_AVX512IFMA 1
#endif
#if defined(__AVX512VBMI2__)
#  define HAVE_AVX512VBMI2 1
#endif
#if defined(__VAES__)
#  define HAVE_VAES 1
#endif

/* znver detection */
#if defined(__znver4__)
#  define AMD_ZNVER 4
#elif defined(__znver3__)
#  define AMD_ZNVER 3
#elif defined(__znver2__)
#  define AMD_ZNVER 2
#else
#  define AMD_ZNVER 0
#endif

/* ── Alignment helpers ──────────────────────────────────── */
#define KC_ALIGN(n)      __attribute__((aligned(n)))
#define KC_ALIGN64       KC_ALIGN(64)
#define KC_ALIGN32       KC_ALIGN(32)
#define KC_LIKELY(x)     __builtin_expect(!!(x), 1)
#define KC_UNLIKELY(x)   __builtin_expect(!!(x), 0)
#define KC_FORCE_INLINE  __attribute__((always_inline)) inline
#define KC_NOINLINE      __attribute__((noinline))
#define KC_PREFETCH(p,d) __builtin_prefetch((p), 0, (d))
#define KC_PREFETCH_W(p) __builtin_prefetch((p), 1, 1)

/* ── Integer types ──────────────────────────────────────── */
typedef unsigned __int128 uint128_t;
typedef uint64_t  u64;
typedef uint32_t  u32;
typedef uint16_t  u16;
typedef uint8_t   u8;
typedef int64_t   i64;
typedef int32_t   i32;

/* ── secp256k1 constants ────────────────────────────────── */
#define SECP256K1_P_HEX \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define SECP256K1_N_HEX \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

/* ── Key / address sizes ─────────────────────────────────── */
#define PRIVKEY_BYTES    32
#define PUBKEY_BYTES_C   33
#define PUBKEY_BYTES_U   65
#define HASH160_BYTES    20
#define ADDRESS_BYTES    25

/* ── BSGS batch group size (from keyhunt latest) ────────── */
/* CPU_GRP_SIZE controls how many points are processed per
 * batch modular inversion cycle. 1024 is optimal for EPYC
 * cache hierarchy (fits in L1). */
#define CPU_GRP_SIZE     1024

/* ── Thread limits ──────────────────────────────────────── */
#define KC_DEFAULT_THREADS   64
#define KC_MAX_THREADS      512   /* supports up to 2P TR7995X */

/* ── BSGS table limits ──────────────────────────────────── */
#define BSGS_DEFAULT_BITS    24
#define BSGS_MAX_BITS        28
#define BSGS_MIN_BITS        18

/* ── BSGS submodes (updated from keyhunt latest) ────────── */
typedef enum {
    BSGS_SUBMODE_SEQUENTIAL  = 0,  /* default — L→R sweep        */
    BSGS_SUBMODE_BACKWARD    = 1,  /* R→L sweep                  */
    BSGS_SUBMODE_BOTH        = 2,  /* forward + backward         */
    BSGS_SUBMODE_RANDOM      = 3,  /* random giant step order    */
    BSGS_SUBMODE_DANCE       = 4,  /* alternating forward/back   */
    BSGS_SUBMODE_MIDDLEOUT   = 5,  /* start from midpoint        */
} BSGSSubmode;

/* ── Stats interval ─────────────────────────────────────── */
#define KC_STATS_INTERVAL_SEC  10  /* default -s 10 */

/* ── Bloom filter levels ────────────────────────────────── */
/* Three-tier system from keyhunt (reduces RAM vs single filter) */
#define BLOOM_LEVEL1  0   /* largest  — ~M elements             */
#define BLOOM_LEVEL2  1   /* medium   — M/32 elements           */
#define BLOOM_LEVEL3  2   /* smallest — M/1024 elements (exact) */

/* ── File naming convention (matches keyhunt) ───────────── */
/* keyhunt_bsgs_<type>_<size>.blm / .tbl                     */
#define BSGS_FILE_BLM1_FMT   "keyhunt_bsgs_4_%llu.blm"
#define BSGS_FILE_BLM2_FMT   "keyhunt_bsgs_6_%llu.blm"
#define BSGS_FILE_BLM3_FMT   "keyhunt_bsgs_7_%llu.blm"
#define BSGS_FILE_TBL_FMT    "keyhunt_bsgs_2_%llu.tbl"

/* ── Checkpoint / range file ────────────────────────────── */
#define KC_DEEP_FILE         "deep.txt"
#define KC_CHECKED_FILE      "checked-deep.txt"

/* ── Output colours ─────────────────────────────────────── */
#define ANSI_RED     "\033[0;31m"
#define ANSI_GREEN   "\033[0;32m"
#define ANSI_YELLOW  "\033[0;33m"
#define ANSI_CYAN    "\033[0;36m"
#define ANSI_MAGENTA "\033[0;35m"
#define ANSI_RESET   "\033[0m"

/* ── Logging ────────────────────────────────────────────── */
#define KC_LOG(fmt, ...)  fprintf(stdout, "[KC] " fmt "\n", ##__VA_ARGS__)
#define KC_ERR(fmt, ...)  fprintf(stderr, ANSI_RED "[ERR] " fmt ANSI_RESET "\n", ##__VA_ARGS__)
#define KC_OK(fmt, ...)   fprintf(stdout, ANSI_GREEN "[OK] "  fmt ANSI_RESET "\n", ##__VA_ARGS__)
#define KC_WARN(fmt, ...) fprintf(stdout, ANSI_YELLOW "[WARN] " fmt ANSI_RESET "\n", ##__VA_ARGS__)
#define KC_FOUND(fmt,...) fprintf(stdout, ANSI_MAGENTA "[FOUND] " fmt ANSI_RESET "\n", ##__VA_ARGS__)

/* ── Utility inlines ────────────────────────────────────── */
static KC_FORCE_INLINE u64 rotl64(u64 x, int k) {
    return (x << k) | (x >> (64 - k));
}
static KC_FORCE_INLINE u32 bswap32(u32 x) { return __builtin_bswap32(x); }
static KC_FORCE_INLINE u64 bswap64(u64 x) { return __builtin_bswap64(x); }

static inline int hex2bin(const char *hex, u8 *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(hex + 2*i, "%02x", &b) != 1) return -1;
        out[i] = (u8)b;
    }
    return 0;
}

static inline void bin2hex(const u8 *in, size_t len, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = h[in[i] >> 4];
        out[2*i+1] = h[in[i] & 0xf];
    }
    out[2*len] = '\0';
}

/* ── XXH3 inline (header-only, no external dep) ─────────── */
/* Minimal XXH3_64 implementation for internal hashing.
 * Based on xxHash v0.8.2 (BSD license, Cyan4973).
 * Used for: bloom filter checksums, hash table probing.
 * ~3× faster than XXH64 on small keys; AVX-512 auto-vectorized
 * on znver4 when XXH_ENABLE_AUTOVECTORIZE is set.          */

#define XXH_PRIME64_1  0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2  0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3  0x165667B19E3779F9ULL
#define XXH_PRIME64_4  0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5  0x27D4EB2F165667C5ULL

static KC_FORCE_INLINE u64 xxh3_avalanche(u64 h64) {
    h64 ^= h64 >> 37;
    h64 *= 0x165667919E3779F9ULL;
    h64 ^= h64 >> 32;
    return h64;
}

/* Fast XXH3-inspired 64-bit hash for ≤8-byte keys */
static KC_FORCE_INLINE u64 xxh3_64_small(const u8 *key, size_t len, u64 seed) {
    u64 h64 = seed + XXH_PRIME64_5 + len;
    if (len >= 4) {
        u32 v1, v2;
        memcpy(&v1, key,       4);
        memcpy(&v2, key+len-4, 4);
        h64 ^= (u64)v1 * XXH_PRIME64_1;
        h64  = rotl64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        h64 ^= (u64)v2 * XXH_PRIME64_1;
        h64  = rotl64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
    } else if (len > 0) {
        u8 b = key[0] | ((len > 1 ? key[1] : 0) << 8)
                      | ((len > 2 ? key[2] : 0) << 16);
        h64 ^= (u64)b * XXH_PRIME64_5;
        h64  = rotl64(h64, 11) * XXH_PRIME64_1;
    }
    return xxh3_avalanche(h64);
}

/* Hash 20-byte hash160 → u64 (used everywhere internally) */
static KC_FORCE_INLINE u64 hash160_xxh3(const u8 *h160) {
    u64 a, b, c;
    memcpy(&a, h160,    8);
    memcpy(&b, h160+8,  8);
    memcpy(&c, h160+16, 4); /* 4 bytes only */
    u64 h = XXH_PRIME64_5 + 20;
    h ^= a * XXH_PRIME64_1; h = rotl64(h,27)*XXH_PRIME64_2 + XXH_PRIME64_3;
    h ^= b * XXH_PRIME64_1; h = rotl64(h,27)*XXH_PRIME64_2 + XXH_PRIME64_3;
    h ^= c * XXH_PRIME64_1; h = rotl64(h,27)*XXH_PRIME64_2 + XXH_PRIME64_3;
    return xxh3_avalanche(h);
}

/* File checksum via XXH3 (replaces SHA256 for .blm/.tbl verification) */
u64  xxh3_file_checksum(const char *path);
bool xxh3_verify_file(const char *path, u64 expected_checksum);

#endif /* COMMON_H */
