/*============================================================
 * Keyhunt-Cyclone — src/util.c  (v2 — 2025)
 * Utility functions: XXH3 streaming, string helpers,
 * scalar print, memory reporting
 *============================================================*/

#include "keyhunt.h"
#include <sys/resource.h>
#include <time.h>

/* ── XXH3 streaming file checksum ───────────────────────── */
/* Full-file variant using 64KB read blocks                  */
u64 xxh3_file_checksum(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0ULL;

    u64 h = XXH_PRIME64_5;
    u8  buf[65536];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        size_t i = 0;
        /* Process 8-byte chunks */
        for (; i + 8 <= n; i += 8) {
            u64 chunk;
            memcpy(&chunk, buf + i, 8);
            h ^= chunk * XXH_PRIME64_1;
            h  = rotl64(h, 27) * XXH_PRIME64_2 + XXH_PRIME64_3;
        }
        /* Remaining bytes */
        if (i < n) {
            u64 chunk = 0;
            memcpy(&chunk, buf + i, n - i);
            h ^= chunk * XXH_PRIME64_1;
            h  = rotl64(h, 27) * XXH_PRIME64_2 + XXH_PRIME64_3;
        }
    }
    fclose(fp);

    /* Final avalanche */
    h ^= h >> 37;
    h *= 0x165667919E3779F9ULL;
    h ^= h >> 32;
    return h;
}

bool xxh3_verify_file(const char *path, u64 expected) {
    u64 actual = xxh3_file_checksum(path);
    if (actual != expected) {
        KC_WARN("Checksum mismatch for %s: got 0x%016llX expected 0x%016llX",
                path, (unsigned long long)actual,
                (unsigned long long)expected);
        return false;
    }
    return true;
}

/* ── Scalar print helpers ────────────────────────────────── */
void scalar_print_hex(const char *label, const Scalar *s) {
    u8 b[32]; scalar_to_bytes(s, b);
    char hex[65]; bin2hex(b, 32, hex);
    printf("  %s: %s\n", label, hex);
}

/* ── Memory reporting ────────────────────────────────────── */
void print_memory_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        long kb = usage.ru_maxrss;
#ifdef __APPLE__
        kb /= 1024;  /* macOS reports bytes */
#endif
        KC_LOG("Peak memory usage: %ld MB", kb / 1024);
    }
}

/* ── Human-readable size ─────────────────────────────────── */
void format_bytes(u64 bytes, char *out, size_t outlen) {
    if (bytes >= (1ULL << 30))
        snprintf(out, outlen, "%.2f GB", bytes / (double)(1ULL<<30));
    else if (bytes >= (1ULL << 20))
        snprintf(out, outlen, "%.2f MB", bytes / (double)(1ULL<<20));
    else if (bytes >= (1ULL << 10))
        snprintf(out, outlen, "%.2f KB", bytes / (double)(1ULL<<10));
    else
        snprintf(out, outlen, "%llu B", (unsigned long long)bytes);
}

/* ── Speed formatter ─────────────────────────────────────── */
void format_rate(double keys_per_sec, char *out, size_t outlen) {
    if (keys_per_sec >= 1e12)
        snprintf(out, outlen, "%.3f Tkeys/s", keys_per_sec / 1e12);
    else if (keys_per_sec >= 1e9)
        snprintf(out, outlen, "%.3f Gkeys/s", keys_per_sec / 1e9);
    else if (keys_per_sec >= 1e6)
        snprintf(out, outlen, "%.3f Mkeys/s", keys_per_sec / 1e6);
    else
        snprintf(out, outlen, "%.1f keys/s",  keys_per_sec);
}

/* ── Timestamp string ────────────────────────────────────── */
void get_timestamp(char *out, size_t outlen) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(out, outlen, "%Y-%m-%d %H:%M:%S", tm);
}

/* ── System info ─────────────────────────────────────────── */
void print_system_info(void) {
    printf("System:\n");
    printf("  Logical CPUs:  %ld\n", sysconf(_SC_NPROCESSORS_ONLN));
    printf("  Physical RAM:  ");
    long pages     = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && page_size > 0) {
        u64 ram = (u64)pages * (u64)page_size;
        char buf[32]; format_bytes(ram, buf, sizeof(buf));
        printf("%s\n", buf);
    } else {
        printf("(unknown)\n");
    }
}

/* ── Bloom filter memory estimate ────────────────────────── */
void estimate_bloom_memory(u64 M, int k_factor, char *out, size_t outlen) {
    /* Three-tier bloom: L1=M, L2=M/32, L3=M/1024 elements
     * Each element costs ~ -ln(fpr) / ln(2)^2 bits ≈ 9.6 bits at fpr=0.00001 */
    double bits_per_elem = 9.6;
    u64 total_bits = (u64)((double)(M + M/32 + M/1024) * bits_per_elem);
    u64 bp_bytes   = (M / 1024) * sizeof(u64) * 2;  /* bP exact table */
    u64 total_bytes= total_bits / 8 + bp_bytes;
    total_bytes    *= (u64)k_factor;

    format_bytes(total_bytes, out, outlen);
}

/* ── Range estimate ──────────────────────────────────────── */
void estimate_search_time(u64 range_size, double tkeys_per_sec,
                           char *out, size_t outlen) {
    if (tkeys_per_sec <= 0) {
        snprintf(out, outlen, "unknown");
        return;
    }
    double secs = (double)range_size / tkeys_per_sec;
    if (secs < 60)
        snprintf(out, outlen, "%.1f seconds", secs);
    else if (secs < 3600)
        snprintf(out, outlen, "%.1f minutes", secs / 60);
    else if (secs < 86400)
        snprintf(out, outlen, "%.1f hours",   secs / 3600);
    else if (secs < 86400 * 365)
        snprintf(out, outlen, "%.1f days",    secs / 86400);
    else
        snprintf(out, outlen, "%.1f years",   secs / (86400*365));
}

/* ── Atomic u64 add (portable) ───────────────────────────── */
void atomic_add_u64(volatile u64 *ptr, u64 val) {
    __atomic_add_fetch(ptr, val, __ATOMIC_RELAXED);
}

/* ── Random scalar in [lo, hi] ───────────────────────────── */
void scalar_random_in_range(Scalar *out, const Scalar *lo, const Scalar *hi) {
    Scalar width;
    scalar_sub(&width, hi, lo);
    /* Generate random 256-bit value, reduce to width */
    Scalar rnd;
    for (int i = 0; i < 4; i++)
        rnd.d[i] = ((u64)lrand48() << 32) | (u64)lrand48();
    /* Simple modular reduction (approximate for large width) */
    if (width.d[3] == 0 && width.d[2] == 0 && width.d[1] == 0) {
        rnd.d[0] = rnd.d[0] % (width.d[0] + 1);
        rnd.d[1] = rnd.d[2] = rnd.d[3] = 0;
    }
    scalar_add(out, lo, &rnd);
}
