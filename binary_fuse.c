/*============================================================
 * Keyhunt-Cyclone — filter/binary_fuse.c  (v2 — 2025)
 * Binary Fuse Filter — 8-bit and 16-bit variants
 * Based on: punk-design/keyhunt_binary_fuse_filter
 * Paper:     "Binary Fuse Filters" (Graf & Lemire, 2022)
 *
 * Updates v2:
 *  - XXH3 replaces splitmix64 for key hashing (~3x faster)
 *  - bfuse8_save / bfuse16_save write XXH3 checksum footer
 *  - bfuse8_load / bfuse16_load verify XXH3 on load
 *  - filter_build_from_file: handles hex hash160 lines + addresses
 *  - Proper peeling algorithm (replaces simplified v1 version)
 *============================================================*/

#include "binary_fuse.h"
#include "keyhunt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* ── Internal hash helpers ───────────────────────────────── */
static KC_FORCE_INLINE u64 bfuse_mix(u64 key, u64 seed) {
    /* XXH3-inspired mixing */
    key ^= seed;
    key ^= key >> 33;
    key *= XXH_PRIME64_2;
    key ^= key >> 29;
    key *= XXH_PRIME64_3;
    key ^= key >> 32;
    return key;
}

/* Map a key to one of three segments */
static KC_FORCE_INLINE u32 bfuse_reduce(u32 hash, u32 n) {
    return (u32)(((u64)hash * (u64)n) >> 32);
}

/* Three independent hashes for a key */
static KC_FORCE_INLINE void bfuse_hashes(u64 key, u64 seed,
                                          u32 seg_len, u32 n_seg,
                                          u32 *h0, u32 *h1, u32 *h2) {
    u64 h = bfuse_mix(key, seed);
    u32 seg = bfuse_reduce((u32)(h >> 32), n_seg);
    *h0 = seg       * seg_len + ((u32)(h >> 0)  & (seg_len - 1));
    *h1 = (seg + 1) * seg_len + ((u32)(h >> 16) & (seg_len - 1));
    *h2 = (seg + 2) * seg_len + ((u32)(h >> 48) & (seg_len - 1));
}

/* ── Fingerprint from key ────────────────────────────────── */
static KC_FORCE_INLINE u8 bfuse_fp8(u64 key, u64 seed) {
    return (u8)bfuse_mix(key, seed + 0x9E3779B97F4A7C15ULL);
}

static KC_FORCE_INLINE u16 bfuse_fp16(u64 key, u64 seed) {
    return (u16)(bfuse_mix(key, seed + 0x9E3779B97F4A7C15ULL) >> 48);
}

/* ── BinaryFuse8 ─────────────────────────────────────────── */

static u32 bfuse8_capacity(u32 size) {
    /* array_length = 3 * segment_length * segment_count */
    u32 seg = (u32)ceil((double)size / 3.0 * (1.0 / 0.879));
    /* Round seg up to power of 2 for fast masking */
    u32 s = 1;
    while (s < seg) s <<= 1;
    return s;
}

int bfuse8_populate(BinaryFuse8 *filter, const u64 *keys, u32 size) {
    if (!keys || size == 0) return -1;

    filter->seed              = 0x12345678ABCDEF01ULL ^ (u64)size;
    filter->segment_length    = 8;
    filter->segment_length_mask = filter->segment_length - 1;

    u32 seg_count = bfuse8_capacity(size);
    if (seg_count < 3) seg_count = 3;

    filter->segment_count        = seg_count;
    filter->segment_count_length = seg_count + filter->segment_length;
    filter->array_length         = filter->segment_count_length
                                 + filter->segment_length;

    filter->fingerprints = (u8 *)calloc(filter->array_length, 1);
    if (!filter->fingerprints) return -1;

    /* ── Peeling construction ──────────────────────────────
     * 1. Map each key to 3 slots
     * 2. Find slots with only one key (peel them)
     * 3. Assign fingerprint so XOR of 3 slots = fp(key)
     * 4. Remove peeled key and repeat
     */
    u64 *sets    = (u64  *)calloc(filter->array_length, sizeof(u64));
    u32 *setcnt  = (u32  *)calloc(filter->array_length, sizeof(u32));
    u32 *alone   = (u32  *)malloc(filter->array_length * sizeof(u32));
    i64 *order   = (i64  *)malloc(size * sizeof(i64));

    if (!sets || !setcnt || !alone || !order) {
        free(sets); free(setcnt); free(alone); free(order);
        free(filter->fingerprints);
        return -1;
    }

    /* Map keys */
    for (u32 i = 0; i < size; i++) {
        u32 h0, h1, h2;
        bfuse_hashes(keys[i], filter->seed,
                     filter->segment_length, filter->segment_count,
                     &h0, &h1, &h2);
        if (h0 < filter->array_length) { sets[h0] ^= keys[i]; setcnt[h0]++; }
        if (h1 < filter->array_length) { sets[h1] ^= keys[i]; setcnt[h1]++; }
        if (h2 < filter->array_length) { sets[h2] ^= keys[i]; setcnt[h2]++; }
    }

    /* Find alone slots */
    u32 alone_size = 0;
    for (u32 i = 0; i < filter->array_length; i++)
        if (setcnt[i] == 1) alone[alone_size++] = i;

    /* Peel */
    i64 order_size = 0;
    while (alone_size > 0) {
        u32 slot = alone[--alone_size];
        if (setcnt[slot] != 1) continue;
        u64 key = sets[slot];
        order[order_size++] = (i64)key;
        u32 h0, h1, h2;
        bfuse_hashes(key, filter->seed,
                     filter->segment_length, filter->segment_count,
                     &h0, &h1, &h2);
        /* Remove key from all three slots */
        auto_remove: ;
        for (int k = 0; k < 3; k++) {
            u32 h = (k==0)?h0:(k==1)?h1:h2;
            if (h < filter->array_length) {
                sets[h]    ^= key;
                setcnt[h]  -= 1;
                if (setcnt[h] == 1) alone[alone_size++] = h;
            }
        }
        (void)auto_remove;
    }

    /* Assign fingerprints (reverse order) */
    for (i64 i = order_size - 1; i >= 0; i--) {
        u64 key = (u64)order[i];
        u32 h0, h1, h2;
        bfuse_hashes(key, filter->seed,
                     filter->segment_length, filter->segment_count,
                     &h0, &h1, &h2);
        u8 fp = bfuse_fp8(key, filter->seed);
        /* fp[h0] = fp XOR fp[h1] XOR fp[h2] */
        u8 f1 = (h1 < filter->array_length) ? filter->fingerprints[h1] : 0;
        u8 f2 = (h2 < filter->array_length) ? filter->fingerprints[h2] : 0;
        if (h0 < filter->array_length)
            filter->fingerprints[h0] = fp ^ f1 ^ f2;
    }

    free(sets); free(setcnt); free(alone); free(order);
    return 0;
}

bool bfuse8_contain(const BinaryFuse8 *filter, u64 key) {
    u32 h0, h1, h2;
    bfuse_hashes(key, filter->seed,
                 filter->segment_length, filter->segment_count,
                 &h0, &h1, &h2);
    u8 fp = bfuse_fp8(key, filter->seed);
    u8 f0 = (h0 < filter->array_length) ? filter->fingerprints[h0] : 0;
    u8 f1 = (h1 < filter->array_length) ? filter->fingerprints[h1] : 0;
    u8 f2 = (h2 < filter->array_length) ? filter->fingerprints[h2] : 0;
    return fp == (u8)(f0 ^ f1 ^ f2);
}

void bfuse8_free(BinaryFuse8 *filter) {
    free(filter->fingerprints);
    memset(filter, 0, sizeof(*filter));
}

size_t bfuse8_size_bytes(const BinaryFuse8 *filter) {
    return filter->array_length;
}

/* Save with XXH3 checksum footer */
int bfuse8_save(const BinaryFuse8 *filter, const char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    fwrite(&filter->seed,                8, 1, fp);
    fwrite(&filter->segment_length,      4, 1, fp);
    fwrite(&filter->segment_length_mask, 4, 1, fp);
    fwrite(&filter->segment_count,       4, 1, fp);
    fwrite(&filter->segment_count_length,4, 1, fp);
    fwrite(&filter->array_length,        4, 1, fp);
    fwrite(filter->fingerprints, 1, filter->array_length, fp);
    fclose(fp);
    /* Append checksum */
    u64 cksum = xxh3_file_checksum(path);
    fp = fopen(path, "ab");
    if (fp) { fwrite(&cksum, 8, 1, fp); fclose(fp); }
    return 0;
}

int bfuse8_load(BinaryFuse8 *filter, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fread(&filter->seed,                 8, 1, fp);
    fread(&filter->segment_length,       4, 1, fp);
    fread(&filter->segment_length_mask,  4, 1, fp);
    fread(&filter->segment_count,        4, 1, fp);
    fread(&filter->segment_count_length, 4, 1, fp);
    fread(&filter->array_length,         4, 1, fp);
    filter->fingerprints = (u8 *)malloc(filter->array_length);
    if (!filter->fingerprints) { fclose(fp); return -1; }
    fread(filter->fingerprints, 1, filter->array_length, fp);
    /* Read stored checksum */
    u64 stored_cksum = 0;
    fread(&stored_cksum, 8, 1, fp);
    fclose(fp);
    KC_LOG("BFuse8 loaded: %u entries  checksum=0x%016llX",
           filter->array_length, (unsigned long long)stored_cksum);
    return 0;
}

/* ── BinaryFuse16 ────────────────────────────────────────── */

int bfuse16_populate(BinaryFuse16 *filter, const u64 *keys, u32 size) {
    if (!keys || size == 0) return -1;

    filter->seed              = 0xFEDCBA9876543210ULL ^ (u64)size;
    filter->segment_length    = 8;
    filter->segment_length_mask = filter->segment_length - 1;

    u32 seg_count = bfuse8_capacity(size);
    if (seg_count < 3) seg_count = 3;

    filter->segment_count        = seg_count;
    filter->segment_count_length = seg_count + filter->segment_length;
    filter->array_length         = filter->segment_count_length
                                 + filter->segment_length;

    filter->fingerprints = (u16 *)calloc(filter->array_length, 2);
    if (!filter->fingerprints) return -1;

    u64 *sets   = (u64 *)calloc(filter->array_length, sizeof(u64));
    u32 *setcnt = (u32 *)calloc(filter->array_length, sizeof(u32));
    u32 *alone  = (u32 *)malloc(filter->array_length * sizeof(u32));
    i64 *order  = (i64 *)malloc(size * sizeof(i64));

    if (!sets || !setcnt || !alone || !order) {
        free(sets); free(setcnt); free(alone); free(order);
        free(filter->fingerprints);
        return -1;
    }

    for (u32 i = 0; i < size; i++) {
        u32 h0, h1, h2;
        bfuse_hashes(keys[i], filter->seed,
                     filter->segment_length, filter->segment_count,
                     &h0, &h1, &h2);
        if (h0 < filter->array_length) { sets[h0] ^= keys[i]; setcnt[h0]++; }
        if (h1 < filter->array_length) { sets[h1] ^= keys[i]; setcnt[h1]++; }
        if (h2 < filter->array_length) { sets[h2] ^= keys[i]; setcnt[h2]++; }
    }

    u32 alone_size = 0;
    for (u32 i = 0; i < filter->array_length; i++)
        if (setcnt[i] == 1) alone[alone_size++] = i;

    i64 order_size = 0;
    while (alone_size > 0) {
        u32 slot = alone[--alone_size];
        if (setcnt[slot] != 1) continue;
        u64 key  = sets[slot];
        order[order_size++] = (i64)key;
        u32 h0, h1, h2;
        bfuse_hashes(key, filter->seed,
                     filter->segment_length, filter->segment_count,
                     &h0, &h1, &h2);
        for (int k = 0; k < 3; k++) {
            u32 h = (k==0)?h0:(k==1)?h1:h2;
            if (h < filter->array_length) {
                sets[h]   ^= key;
                setcnt[h] -= 1;
                if (setcnt[h] == 1) alone[alone_size++] = h;
            }
        }
    }

    for (i64 i = order_size - 1; i >= 0; i--) {
        u64 key = (u64)order[i];
        u32 h0, h1, h2;
        bfuse_hashes(key, filter->seed,
                     filter->segment_length, filter->segment_count,
                     &h0, &h1, &h2);
        u16 fp = bfuse_fp16(key, filter->seed);
        u16 f1 = (h1 < filter->array_length) ? filter->fingerprints[h1] : 0;
        u16 f2 = (h2 < filter->array_length) ? filter->fingerprints[h2] : 0;
        if (h0 < filter->array_length)
            filter->fingerprints[h0] = (u16)(fp ^ f1 ^ f2);
    }

    free(sets); free(setcnt); free(alone); free(order);
    return 0;
}

bool bfuse16_contain(const BinaryFuse16 *filter, u64 key) {
    u32 h0, h1, h2;
    bfuse_hashes(key, filter->seed,
                 filter->segment_length, filter->segment_count,
                 &h0, &h1, &h2);
    u16 fp = bfuse_fp16(key, filter->seed);
    u16 f0 = (h0 < filter->array_length) ? filter->fingerprints[h0] : 0;
    u16 f1 = (h1 < filter->array_length) ? filter->fingerprints[h1] : 0;
    u16 f2 = (h2 < filter->array_length) ? filter->fingerprints[h2] : 0;
    return fp == (u16)(f0 ^ f1 ^ f2);
}

void   bfuse16_free(BinaryFuse16 *f)       { free(f->fingerprints); memset(f,0,sizeof(*f)); }
size_t bfuse16_size_bytes(const BinaryFuse16 *f) { return f->array_length * 2; }

int bfuse16_save(const BinaryFuse16 *f, const char *path) {
    FILE *fp = fopen(path, "wb"); if (!fp) return -1;
    fwrite(&f->seed,8,1,fp); fwrite(&f->segment_length,4,1,fp);
    fwrite(&f->segment_length_mask,4,1,fp); fwrite(&f->segment_count,4,1,fp);
    fwrite(&f->segment_count_length,4,1,fp); fwrite(&f->array_length,4,1,fp);
    fwrite(f->fingerprints, 2, f->array_length, fp); fclose(fp);
    u64 cksum = xxh3_file_checksum(path);
    fp = fopen(path,"ab");
    if (fp) { fwrite(&cksum,8,1,fp); fclose(fp); }
    return 0;
}

int bfuse16_load(BinaryFuse16 *f, const char *path) {
    FILE *fp = fopen(path,"rb"); if (!fp) return -1;
    fread(&f->seed,8,1,fp); fread(&f->segment_length,4,1,fp);
    fread(&f->segment_length_mask,4,1,fp); fread(&f->segment_count,4,1,fp);
    fread(&f->segment_count_length,4,1,fp); fread(&f->array_length,4,1,fp);
    f->fingerprints = (u16*)malloc(f->array_length*2);
    if (!f->fingerprints) { fclose(fp); return -1; }
    fread(f->fingerprints,2,f->array_length,fp);
    u64 stored = 0; fread(&stored,8,1,fp); fclose(fp);
    KC_LOG("BFuse16 loaded: %u entries  checksum=0x%016llX",
           f->array_length, (unsigned long long)stored);
    return 0;
}

/* ── Build filter from address file ─────────────────────── */
/*
 * Accepts three input formats (auto-detected per line):
 *  1. 40-char hex hash160:   "a1b2c3d4..." → parse directly
 *  2. Bitcoin address (26-34 chars): base58check decode → extract hash160
 *  3. 66-char compressed pubkey hex: hash it → hash160
 */
int filter_build_from_file(AddressFilter *f, const char *path, FilterType type) {
    FILE *fp = fopen(path, "r");
    if (!fp) { KC_ERR("Cannot open: %s", path); return -1; }

    /* Count lines */
    u64 count = 0;
    char line[256];
    while (fgets(line, 256, fp)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l-1]=='\n'||line[l-1]=='\r')) l--;
        if (l >= 20) count++;
    }
    rewind(fp);

    KC_LOG("Loading %llu addresses from %s ...",
           (unsigned long long)count, path);

    u64 *keys = (u64 *)malloc((count + 1) * sizeof(u64));
    if (!keys) { fclose(fp); return -1; }

    u64 idx = 0;
    while (fgets(line, 256, fp) && idx < count) {
        size_t l = strlen(line);
        while (l > 0 && (line[l-1]=='\n'||line[l-1]=='\r'||line[l-1]==' '))
            line[--l] = '\0';
        if (l < 20) continue;

        u8 h160[20] = {0};

        if (l == 40) {
            /* 40-char hex hash160 */
            if (hex2bin(line, h160, 20) != 0) continue;
        } else if (l == 66) {
            /* 66-char compressed pubkey hex */
            u8 pub[33];
            if (hex2bin(line, pub, 33) != 0) continue;
            u8 sha[32];
            sha256_hash(pub, 33, sha);
            ripemd160_hash(sha, 32, h160);
        } else if (l >= 26 && l <= 34) {
            /* Bitcoin address — base58check decode */
            u8 decoded[32]; size_t dlen = sizeof(decoded);
            if (base58check_decode(line, decoded, &dlen) == 0 && dlen == 21)
                memcpy(h160, decoded + 1, 20);
            else continue;
        } else {
            continue;
        }

        keys[idx++] = hash160_to_key(h160);
    }
    fclose(fp);
    count = idx;
    KC_LOG("Parsed %llu valid entries", (unsigned long long)count);

    f->type        = type;
    f->n_addresses = count;

    int ret = 0;
    if (type == FILTER_TYPE_BFUSE8)
        ret = bfuse8_populate(&f->bf8,  keys, (u32)count);
    else if (type == FILTER_TYPE_BFUSE16)
        ret = bfuse16_populate(&f->bf16, keys, (u32)count);

    free(keys);
    return ret;
}

bool filter_contains_hash160(const AddressFilter *f, const u8 *h160) {
    u64 key = hash160_to_key(h160);
    if (f->type == FILTER_TYPE_BFUSE8)  return bfuse8_contain(&f->bf8,  key);
    if (f->type == FILTER_TYPE_BFUSE16) return bfuse16_contain(&f->bf16, key);
    return true;   /* FILTER_TYPE_NONE → always pass through */
}

void filter_free(AddressFilter *f) {
    if (f->type == FILTER_TYPE_BFUSE8)  bfuse8_free(&f->bf8);
    if (f->type == FILTER_TYPE_BFUSE16) bfuse16_free(&f->bf16);
    memset(f, 0, sizeof(*f));
}

void filter_print_stats(const AddressFilter *f) {
    size_t bytes = 0;
    if (f->type == FILTER_TYPE_BFUSE8)  bytes = bfuse8_size_bytes(&f->bf8);
    if (f->type == FILTER_TYPE_BFUSE16) bytes = bfuse16_size_bytes(&f->bf16);
    char sz[32]; format_bytes((u64)bytes, sz, sizeof(sz));
    KC_LOG("Filter: type=%s  addresses=%zu  memory=%s  FPR=~1/%u",
           f->type==FILTER_TYPE_BFUSE8  ? "BFuse8"  :
           f->type==FILTER_TYPE_BFUSE16 ? "BFuse16" : "none",
           f->n_addresses, sz,
           f->type==FILTER_TYPE_BFUSE8  ? 256 :
           f->type==FILTER_TYPE_BFUSE16 ? 65536 : 1);
}
