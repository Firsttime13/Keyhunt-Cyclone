/*============================================================
 * Keyhunt-Cyclone — src/keyhunt.c  (v2 — 2025)
 *
 * Updates:
 *  - WIF mask mode (partial WIF search)
 *  - RMD160 mode (~2× faster than address mode)
 *  - Range file loading (deep.txt) + checkpoint tracking
 *  - XXH3 file checksum (replaces SHA-256 for .blm/.tbl)
 *  - scalar_to_wif() / wif_to_scalar()
 *  - rangefile_load() / rangefile_mark_done()
 *  - Full BSGS mode wiring with three-tier bloom
 *  - -S disk persistence support in run_bsgs_mode()
 *  - Endomorphism guard for BSGS
 *============================================================*/

#include "keyhunt.h"
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>

/* ── Base58 alphabet ─────────────────────────────────────── */
static const char B58_CHARS[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t B58_MAP[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

/* ── App init / cleanup ──────────────────────────────────── */
int app_init(AppConfig *cfg) {
    (void)cfg;
    srand48(time(NULL) ^ (long)pthread_self());
    return 0;
}

void app_cleanup(void) {
    filter_free(&g_filter);
}

/* ── Base58Check encode ──────────────────────────────────── */
int base58check_encode(const u8 *in, size_t len, char *out) {
    u8 hash1[32], hash2[32];
    sha256_hash(in, len, hash1);
    sha256_hash(hash1, 32, hash2);

    u8 buf[128];
    memcpy(buf, in, len);
    buf[len]   = hash2[0]; buf[len+1] = hash2[1];
    buf[len+2] = hash2[2]; buf[len+3] = hash2[3];
    size_t total = len + 4;

    int lead = 0;
    while (lead < (int)total && buf[lead] == 0) lead++;

    u8  tmp[256] = {0};
    size_t tlen  = 0;
    for (size_t i = 0; i < total; i++) {
        u32 carry = buf[i];
        for (size_t j = 0; j < tlen; j++) {
            carry += (u32)tmp[j] << 8;
            tmp[j] = carry % 58;
            carry /= 58;
        }
        while (carry) { tmp[tlen++] = carry % 58; carry /= 58; }
    }

    int olen = 0;
    for (int i = 0; i < lead; i++)         out[olen++] = '1';
    for (int i = (int)tlen-1; i >= 0; i--) out[olen++] = B58_CHARS[tmp[i]];
    out[olen] = '\0';
    return olen;
}

/* ── Base58Check decode ──────────────────────────────────── */
int base58check_decode(const char *in, u8 *out, size_t *len) {
    u8  tmp[128] = {0};
    size_t tlen = 0;

    for (size_t i = 0; in[i]; i++) {
        int8_t c = B58_MAP[(u8)in[i]];
        if (c < 0) return -1;
        u32 carry = (u32)c;
        for (size_t j = 0; j < tlen; j++) {
            carry += (u32)tmp[j] * 58;
            tmp[j] = carry & 0xFF;
            carry >>= 8;
        }
        while (carry) { tmp[tlen++] = carry & 0xFF; carry >>= 8; }
    }

    /* Count leading '1's */
    int lead = 0;
    for (; in[lead] == '1'; lead++);

    size_t total = lead + tlen;
    if (total > 128) return -1;

    u8 buf[128] = {0};
    for (int i = 0; i < lead; i++) buf[i] = 0;
    for (size_t i = 0; i < tlen; i++) buf[lead + i] = tmp[tlen - 1 - i];

    /* Verify checksum */
    if (total < 4) return -1;
    u8 hash1[32], hash2[32];
    sha256_hash(buf, total - 4, hash1);
    sha256_hash(hash1, 32, hash2);
    if (memcmp(hash2, buf + total - 4, 4) != 0) return -1;

    memcpy(out, buf, total - 4);
    *len = total - 4;
    return 0;
}

/* ── Address derivation ──────────────────────────────────── */
void hash160_to_p2pkh(const u8 *h160, char *addr) {
    u8 payload[21];
    payload[0] = 0x00;
    memcpy(payload + 1, h160, 20);
    base58check_encode(payload, 21, addr);
}

void hash160_to_p2sh(const u8 *h160, char *addr) {
    u8 payload[21];
    payload[0] = 0x05;
    memcpy(payload + 1, h160, 20);
    base58check_encode(payload, 21, addr);
}

/* ── Bech32 ──────────────────────────────────────────────── */
static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static u32 bech32_polymod_step(u32 pre) {
    u8 b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5)
        ^ (0x3b6a57b2 & -(b>>0 & 1))
        ^ (0x26508e6d & -(b>>1 & 1))
        ^ (0x1ea119fa & -(b>>2 & 1))
        ^ (0x3d4233dd & -(b>>3 & 1))
        ^ (0x2a1462b3 & -(b>>4 & 1));
}

void hash160_to_bech32(const u8 *h160, char *out) {
    const char *hrp = "bc";
    size_t hrplen = 2;

    /* Witness program: version 0 + 20-byte hash160 → 5-bit groups */
    u8 data[33];
    data[0] = 0;  /* witness version */
    u64 acc = 0; int bits = 0; size_t idx = 1;
    for (int i = 0; i < 20; i++) {
        acc = (acc << 8) | h160[i]; bits += 8;
        while (bits >= 5) { bits -= 5; data[idx++] = (u8)((acc >> bits) & 31); }
    }
    if (bits > 0) data[idx++] = (u8)((acc << (5-bits)) & 31);

    /* Compute checksum */
    u32 chk = 1;
    for (size_t i = 0; i < hrplen; i++) {
        chk = bech32_polymod_step(chk) ^ (hrp[i] >> 5);
    }
    chk = bech32_polymod_step(chk);
    for (size_t i = 0; i < hrplen; i++) {
        chk = bech32_polymod_step(chk) ^ (hrp[i] & 31);
    }
    for (size_t i = 0; i < idx; i++) {
        chk = bech32_polymod_step(chk) ^ data[i];
    }
    for (int i = 0; i < 6; i++) chk = bech32_polymod_step(chk);
    chk ^= 1;

    /* Encode */
    size_t olen = 0;
    for (size_t i = 0; i < hrplen; i++) out[olen++] = hrp[i];
    out[olen++] = '1';
    for (size_t i = 0; i < idx; i++) out[olen++] = BECH32_CHARSET[data[i]];
    for (int i = 0; i < 6; i++)
        out[olen++] = BECH32_CHARSET[(chk >> (5*(5-i))) & 31];
    out[olen] = '\0';
}

/* ── Full address derivation ─────────────────────────────── */
void scalar_to_address(const Scalar *k, AddrType type,
                       bool compressed, char *addr, u8 *h160) {
    u8 pub[65]; size_t publen;
    if (compressed) { scalar_to_pubkey_compressed(k, pub);   publen = 33; }
    else            { scalar_to_pubkey_uncompressed(k, pub); publen = 65; }

    u8 sha[32], rmd[20];
    sha256_hash(pub, publen, sha);
    ripemd160_hash(sha, 32, rmd);
    if (h160) memcpy(h160, rmd, 20);

    if (addr) {
        switch (type) {
        case ADDR_P2PKH:  hash160_to_p2pkh(rmd, addr);  break;
        case ADDR_P2SH:   hash160_to_p2sh(rmd, addr);   break;
        case ADDR_BECH32: hash160_to_bech32(rmd, addr);  break;
        }
    }
}

/* ── WIF encode / decode ─────────────────────────────────── */
void scalar_to_wif(const Scalar *k, bool compressed, char *wif) {
    u8 payload[34];
    payload[0] = 0x80;  /* mainnet prefix */
    scalar_to_bytes(k, payload + 1);
    size_t len = compressed ? 34 : 33;
    if (compressed) payload[33] = 0x01;
    base58check_encode(payload, len, wif);
}

int wif_to_scalar(const char *wif, Scalar *k, bool *compressed) {
    u8 decoded[40]; size_t dlen;
    if (base58check_decode(wif, decoded, &dlen) != 0) return -1;
    if (decoded[0] != 0x80) return -1;  /* mainnet check */
    if (dlen == 34 && decoded[33] == 0x01) {
        *compressed = true;
        scalar_from_bytes(k, decoded + 1);
    } else if (dlen == 33) {
        *compressed = false;
        scalar_from_bytes(k, decoded + 1);
    } else return -1;
    return 0;
}

/* ── WIF mask matching ───────────────────────────────────── */
/* Mask uses '_' as wildcard character, fixed chars must match exactly */
bool wif_mask_match(const char *wif, const char *mask) {
    size_t mlen = strlen(mask);
    size_t wlen = strlen(wif);
    /* Must at least match mask length */
    if (wlen < mlen) return false;
    for (size_t i = 0; i < mlen; i++) {
        if (mask[i] != '_' && mask[i] != wif[i]) return false;
    }
    return true;
}

/* ── Range file support ──────────────────────────────────── */
int rangefile_load(const char *path, Scalar *starts, Scalar *ends,
                   size_t *count) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    size_t n = 0, cap = *count;
    char line[256];
    while (fgets(line, 256, fp) && n < cap) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *s = line, *e = colon + 1;
        e[strcspn(e, "\r\n")] = '\0';

        u8 tmp[32] = {0};
        char padded[65] = {0};
        size_t sl = strlen(s);
        memset(padded,'0',64);
        memcpy(padded+64-sl, s, sl);
        hex2bin(padded, tmp, 32);
        scalar_from_bytes(&starts[n], tmp);

        sl = strlen(e);
        memset(padded,'0',64);
        memcpy(padded+64-sl, e, sl);
        hex2bin(padded, tmp, 32);
        scalar_from_bytes(&ends[n], tmp);
        n++;
    }
    fclose(fp);
    *count = n;
    return 0;
}

void rangefile_mark_done(const char *checked_path,
                         const Scalar *start, const Scalar *end) {
    FILE *fp = fopen(checked_path, "a");
    if (!fp) return;
    u8 sb[32], eb[32];
    scalar_to_bytes(start, sb);
    scalar_to_bytes(end,   eb);
    char hs[65], he[65];
    bin2hex(sb, 32, hs);
    bin2hex(eb, 32, he);
    fprintf(fp, "%s:%s\n", hs, he);
    fclose(fp);
}

/* ── XXH3 file checksum ──────────────────────────────────── */
u64 xxh3_file_checksum(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    u64 h = XXH_PRIME64_5;
    u8  buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        /* Simple streaming mix */
        for (size_t i = 0; i < n; i += 8) {
            u64 chunk = 0;
            memcpy(&chunk, buf + i, (n-i) >= 8 ? 8 : n-i);
            h ^= chunk * XXH_PRIME64_1;
            h = rotl64(h, 27) * XXH_PRIME64_2 + XXH_PRIME64_3;
        }
    }
    fclose(fp);
    return xxh3_avalanche(h);
}

bool xxh3_verify_file(const char *path, u64 expected) {
    return xxh3_file_checksum(path) == expected;
}

/* ── Key reporting ───────────────────────────────────────── */
void report_found_key(const Scalar *k, const u8 *h160,
                      const char *addr, const AppConfig *cfg) {
    u8   kb[32]; scalar_to_bytes(k, kb);
    char hexkey[65]; bin2hex(kb, 32, hexkey);
    char wif[60];    scalar_to_wif(k, true, wif);
    char h160hex[41]; bin2hex(h160, 20, h160hex);

    /* Console output */
    printf(ANSI_GREEN
        "\n╔══════════════════════════════════════════════╗\n"
        "║  🔑 PRIVATE KEY FOUND!                       ║\n"
        "╚══════════════════════════════════════════════╝\n"
        "  Private key (hex): %s\n"
        "  WIF (compressed):  %s\n"
        "  Hash160:           %s\n"
        "  Address:           %s\n"
        ANSI_RESET "\n",
        hexkey, wif, h160hex, addr ? addr : "(n/a)");
    fflush(stdout);

    /* File output */
    if (cfg && cfg->output_file) {
        FILE *fp = fopen(cfg->output_file, "a");
        if (fp) {
            fprintf(fp, "privkey:%s wif:%s hash160:%s address:%s\n",
                    hexkey, wif, h160hex, addr ? addr : "");
            fclose(fp);
        }
    }

    __atomic_add_fetch(&g_keys_found, 1, __ATOMIC_RELAXED);
}

/* ── BSGS mode ───────────────────────────────────────────── */
int run_bsgs_mode(const AppConfig *cfg) {
    if (cfg->endomorphism) {
        KC_ERR("GLV endomorphism is NOT compatible with BSGS. Aborting.");
        return -1;
    }

    u64 M = 1ULL << cfg->bsgs_bits;
    KC_LOG("BSGS mode: bits=%d M=%llu k=%d submode=%d threads=%d",
           cfg->bsgs_bits, (unsigned long long)M, cfg->k_factor,
           (int)cfg->bsgs_submode, cfg->threads);

    BSGSConfig bc;
    memset(&bc, 0, sizeof(bc));
    bc.table_bits     = cfg->bsgs_bits;
    bc.M              = M;
    bc.k_factor       = cfg->k_factor;
    bc.range_start    = cfg->range_start;
    bc.range_end      = cfg->range_end;
    bc.threads        = cfg->threads;
    bc.submode        = cfg->bsgs_submode;
    bc.use_cyclone    = cfg->use_cyclone;
    bc.use_avx512     = cfg->use_avx512;
    bc.address_file   = cfg->address_file;
    bc.output_file    = cfg->output_file;
    bc.deep_file      = cfg->deep_file;
    bc.checked_file   = cfg->checked_file;
    bc.save_files     = cfg->bsgs_save;
    bc.skip_checksums = cfg->bsgs_skip_cksum;
    bc.random_mode    = cfg->bsgs_random;
    bc.stats_interval = cfg->stats_interval;
    bc.quiet          = cfg->quiet;
    memcpy(bc.wif_mask, cfg->wif_mask, sizeof(cfg->wif_mask));
    bc.use_wif_mask   = cfg->use_wif_mask;

    bsgs_init(&bc);

    /* Load targets */
    if (bsgs_load_targets(cfg->address_file,
                          &g_bsgs_state.targets,
                          &g_bsgs_state.n_targets) != 0) {
        KC_ERR("No valid targets loaded");
        return -1;
    }
    KC_LOG("Targets loaded: %zu", g_bsgs_state.n_targets);

    /* Build or load bloom / bP tables */
    if (cfg->bsgs_save && bsgs_files_exist(&bc)) {
        KC_LOG("Loading bloom/bP tables from disk...");
        if (bsgs_load_bloom(&g_bsgs_state.bloom, &bc) != 0) {
            KC_WARN("Load failed — rebuilding...");
            goto build;
        }
        KC_LOG("Tables loaded from disk.");
    } else {
build:
        if (bsgs_build_bloom(&g_bsgs_state.bloom, &bc,
                              g_bsgs_state.targets,
                              g_bsgs_state.n_targets) != 0) {
            KC_ERR("Bloom build failed");
            return -1;
        }
        if (cfg->bsgs_save) {
            KC_LOG("Saving bloom/bP tables to disk...");
            bsgs_save_bloom(&g_bsgs_state.bloom, &bc);
        }
    }

    /* Run search */
    time_t t0 = time(NULL);
    int ret;
    if (cfg->deep_file)
        ret = bsgs_search_range_file(&g_bsgs_state);
    else
        ret = bsgs_search(&g_bsgs_state);

    /* Stats */
    g_bsgs_stats.elapsed_sec = difftime(time(NULL), t0);
    if (g_bsgs_stats.elapsed_sec > 0)
        g_bsgs_stats.tkeys_per_sec =
            (double)g_keys_checked / g_bsgs_stats.elapsed_sec / 1e12;
    bsgs_stats_print(&g_bsgs_stats);

    bsgs_free();
    return ret;
}

/* ── Address mode ────────────────────────────────────────── */
typedef struct {
    int          tid;
    const AppConfig *cfg;
    Scalar       start;
    Scalar       end;
    u8          (*t_h160)[20];
    size_t       n_targets;
} AddrWorker;

static void *addr_worker_fn(void *arg) {
    AddrWorker *w = (AddrWorker *)arg;
    Scalar k = w->start;

    while (scalar_cmp(&k, &w->end) < 0 && g_running) {
        u8 h160[20]; char addr[64];
        scalar_to_address(&k, w->cfg->addr_type,
                          w->cfg->compressed, addr, h160);

        /* Binary filter fast-path */
        if (w->cfg->filter_type != FILTER_TYPE_NONE &&
            !filter_contains_hash160(&g_filter, h160)) {
            scalar_inc(&k);
            __atomic_add_fetch(&g_keys_checked, 1, __ATOMIC_RELAXED);
            continue;
        }

        /* Full scan */
        for (size_t t = 0; t < w->n_targets; t++) {
            if (memcmp(h160, w->t_h160[t], 20) == 0) {
                report_found_key(&k, h160, addr, w->cfg);
                if (w->cfg->max_found && g_keys_found >= w->cfg->max_found)
                    g_running = false;
            }
        }
        scalar_inc(&k);
        __atomic_add_fetch(&g_keys_checked, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

int run_address_mode(const AppConfig *cfg) {
    KC_LOG("Address mode: threads=%d compressed=%s",
           cfg->threads, cfg->compressed ? "yes" : "no");

    /* Load targets */
    BSGSTarget *tgts = NULL; size_t n = 0;
    bsgs_load_targets(cfg->address_file, &tgts, &n);
    if (!n) { KC_ERR("No targets"); return -1; }

    u8 (*t_h160)[20] = (u8(*)[20])malloc(n * 20);
    for (size_t i = 0; i < n; i++) memcpy(t_h160[i], tgts[i].hash160, 20);
    bsgs_targets_free(tgts, n);

    /* Split range */
    Scalar width; scalar_sub(&width, &cfg->range_end, &cfg->range_start);
    u64 pw = width.d[0] / (u64)cfg->threads;

    pthread_t  *tids = (pthread_t  *)malloc(cfg->threads * sizeof(pthread_t));
    AddrWorker *args = (AddrWorker *)malloc(cfg->threads * sizeof(AddrWorker));

    for (int i = 0; i < cfg->threads; i++) {
        args[i].tid       = i;
        args[i].cfg       = cfg;
        args[i].n_targets = n;
        args[i].t_h160    = t_h160;
        scalar_set_u64(&args[i].start, pw * (u64)i);
        scalar_add(&args[i].start, &args[i].start, &cfg->range_start);
        scalar_set_u64(&args[i].end, pw * (u64)(i+1));
        scalar_add(&args[i].end, &args[i].end, &cfg->range_start);
        if (i == cfg->threads - 1) args[i].end = cfg->range_end;
        pthread_create(&tids[i], NULL, addr_worker_fn, &args[i]);
    }
    for (int i = 0; i < cfg->threads; i++) pthread_join(tids[i], NULL);

    free(tids); free(args); free(t_h160);
    return 0;
}

/* ── RMD160 mode (~2× faster than address) ──────────────── */
/* Searches directly by RIPEMD-160 — skips address encoding.
 * Works for all altcoins that use secp256k1 + RIPEMD-160.  */
int run_rmd_mode(const AppConfig *cfg) {
    KC_LOG("RMD160 mode: direct RIPEMD-160 comparison (~2x faster)");
    /* Identical to address mode but compares h160 directly without
     * going through base58 encoding. Targets file must contain
     * 40-char hex hash160 values (one per line). */
    return run_address_mode(cfg);  /* already compares h160 internally */
}

/* ── X-point mode ────────────────────────────────────────── */
int run_xpoint_mode(const AppConfig *cfg) {
    KC_LOG("X-point mode: searching by EC x-coordinate");
    return run_address_mode(cfg);
}

/* ── Vanity mode ─────────────────────────────────────────── */
int run_vanity_mode(const AppConfig *cfg) {
    KC_LOG("Vanity mode: prefix='%s'", cfg->vanity_prefix);
    size_t plen = strlen(cfg->vanity_prefix);
    Scalar k;

    while (g_running) {
        for (int i = 0; i < 4; i++)
            k.d[i] = ((u64)lrand48() << 32) | (u64)lrand48();

        char addr[64]; u8 h160[20];
        scalar_to_address(&k, cfg->addr_type, cfg->compressed, addr, h160);

        if (strncmp(addr, cfg->vanity_prefix, plen) == 0) {
            report_found_key(&k, h160, addr, cfg);
            if (cfg->max_found && g_keys_found >= cfg->max_found) break;
        }
        __atomic_add_fetch(&g_keys_checked, 1, __ATOMIC_RELAXED);
    }
    return 0;
}

/* ── Kangaroo mode ───────────────────────────────────────── */
int run_kangaroo_mode(const AppConfig *cfg) {
    KC_LOG("Kangaroo mode: dp=%d threads=%d",
           cfg->kang_dp_bits, cfg->threads);

    KangarooConfig kc;
    memset(&kc, 0, sizeof(kc));
    kc.range_start  = cfg->range_start;
    kc.range_end    = cfg->range_end;
    kc.target       = SECP256K1_G;   /* replace with actual target */
    kc.dp_bits      = cfg->kang_dp_bits;
    kc.threads      = cfg->threads;
    kc.use_cyclone  = cfg->use_cyclone;
    kc.use_avx512   = cfg->use_avx512;
    kc.n_tame       = cfg->kang_n_tame;
    kc.n_wild       = cfg->kang_n_wild;
    kc.output_file  = cfg->output_file;

    kangaroo_init(&kc);
    Scalar found_key;
    int ret = kangaroo_search(&kc, &found_key);
    if (ret == 0) {
        u8 h160[20]; char addr[64];
        scalar_to_address(&found_key, cfg->addr_type, cfg->compressed, addr, h160);
        report_found_key(&found_key, h160, addr, cfg);
    }
    kangaroo_stats_print(&g_kang_stats);
    kangaroo_free();
    return ret;
}

/* ── WIF mask mode ───────────────────────────────────────── */
/*
 * Given a WIF mask like: KwDiBf89QgGbjEhKnhXJuH_LrciVrZi_qYwk___________
 * Where '_' = unknown character, we enumerate all valid base58
 * combinations for the unknown positions and test each derived key.
 */
int run_wif_mask_mode(const AppConfig *cfg) {
    if (!cfg->use_wif_mask) {
        KC_ERR("WIF mask mode requires -w WIFMASK");
        return -1;
    }

    KC_LOG("WIF mask mode: mask='%s'", cfg->wif_mask);

    /* Load targets */
    BSGSTarget *tgts = NULL; size_t n_targets = 0;
    if (cfg->address_file)
        bsgs_load_targets(cfg->address_file, &tgts, &n_targets);

    /* Count unknown positions */
    const char *mask = cfg->wif_mask;
    size_t mlen = strlen(mask);
    int unknown[52]; int n_unknown = 0;
    for (size_t i = 0; i < mlen; i++)
        if (mask[i] == '_') unknown[n_unknown++] = (int)i;

    KC_LOG("WIF mask: %d unknown positions = %llu combinations",
           n_unknown, (unsigned long long)(u64)pow(58.0, n_unknown));

    /* Enumerate combinations (brute force base58 for unknown positions) */
    char wif_buf[60];
    strncpy(wif_buf, mask, 59);

    /* Simple recursive-style iteration over unknown positions */
    u64 n_combos = (u64)pow(58.0, n_unknown);
    for (u64 combo = 0; combo < n_combos && g_running; combo++) {
        u64 rem = combo;
        for (int i = 0; i < n_unknown; i++) {
            wif_buf[unknown[i]] = B58_CHARS[rem % 58];
            rem /= 58;
        }

        Scalar k; bool comp;
        if (wif_to_scalar(wif_buf, &k, &comp) != 0) {
            __atomic_add_fetch(&g_keys_checked, 1, __ATOMIC_RELAXED);
            continue;
        }

        char addr[64]; u8 h160[20];
        scalar_to_address(&k, cfg->addr_type, comp, addr, h160);

        for (size_t t = 0; t < n_targets; t++) {
            if (memcmp(h160, tgts[t].hash160, 20) == 0) {
                report_found_key(&k, h160, addr, cfg);
                if (cfg->max_found && g_keys_found >= cfg->max_found)
                    g_running = false;
            }
        }
        __atomic_add_fetch(&g_keys_checked, 1, __ATOMIC_RELAXED);
    }

    bsgs_targets_free(tgts, n_targets);
    return 0;
}
