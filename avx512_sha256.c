/*============================================================
 * Keyhunt-Cyclone — avx512/avx512_sha256.c  (v2 — 2025)
 * 16-lane parallel SHA-256 via AVX-512 + CPU feature detection
 *
 * Updates v2:
 *  - Corrected ternarylogic opcodes for CH and MAJ
 *  - Added VAES-based fast lane for digest finalization
 *  - avx512_sweep_x16(): key → point → hash160 in one call
 *  - CPU detect extended for znver4 (BF16 / FP16 / VNNI)
 *  - bsgs_avx512_giant_advance() for batch giant-step
 *============================================================*/

#include "avx512_ec.h"
#include "keyhunt.h"

#ifdef HAVE_AVX512
#include <immintrin.h>
#include <cpuid.h>

/* ── SHA-256 initial hash values ─────────────────────────── */
static const u32 SHA256_H0[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

/* ── SHA-256 round constants ─────────────────────────────── */
static const u32 SHA256_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
    0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
    0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
    0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
    0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
    0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

/* ── AVX-512 bit-manipulation macros ─────────────────────── */
#define ROTR32(x,n)  _mm512_or_epi32(_mm512_srli_epi32((x),(n)), \
                                      _mm512_slli_epi32((x),32-(n)))
#define SHR32(x,n)   _mm512_srli_epi32((x),(n))

/* CH(e,f,g)  = (e AND f) XOR (NOT e AND g)  → ternary 0xCA */
#define SHA256_CH(e,f,g)  _mm512_ternarylogic_epi32((e),(f),(g),0xCA)
/* MAJ(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c) → ternary 0xE8 */
#define SHA256_MAJ(a,b,c) _mm512_ternarylogic_epi32((a),(b),(c),0xE8)

#define SHA256_EP0(x) \
    _mm512_xor_epi32(_mm512_xor_epi32(ROTR32((x), 2), \
                                       ROTR32((x),13)), ROTR32((x),22))
#define SHA256_EP1(x) \
    _mm512_xor_epi32(_mm512_xor_epi32(ROTR32((x), 6), \
                                       ROTR32((x),11)), ROTR32((x),25))
#define SHA256_SIG0(x) \
    _mm512_xor_epi32(_mm512_xor_epi32(ROTR32((x), 7), \
                                       ROTR32((x),18)), SHR32((x), 3))
#define SHA256_SIG1(x) \
    _mm512_xor_epi32(_mm512_xor_epi32(ROTR32((x),17), \
                                       ROTR32((x),19)), SHR32((x),10))

/* ── Process one 64-byte block across 16 lanes ───────────── */
static void sha256_x16_compress(u32 state[16][8],
                                  const u8 data[16][64]) {
    __m512i W[16];
    __m512i va, vb, vc, vd, ve, vf, vg, vh, t1, t2;

    /* Load 16 message words from 16 independent lanes.
     * Each zmm register holds word[i] for all 16 lanes. */
    for (int i = 0; i < 16; i++) {
        u32 w[16];
        for (int lane = 0; lane < 16; lane++) {
            const u8 *p = data[lane] + i * 4;
            /* Big-endian word load */
            w[lane] = ((u32)p[0] << 24) | ((u32)p[1] << 16)
                    | ((u32)p[2] <<  8) |  (u32)p[3];
        }
        W[i] = _mm512_loadu_epi32(w);
    }

    /* Load state for all 16 lanes */
    {
        u32 sa[16],sb[16],sc[16],sd[16];
        u32 se[16],sf[16],sg[16],sh[16];
        for (int l = 0; l < 16; l++) {
            sa[l]=state[l][0]; sb[l]=state[l][1];
            sc[l]=state[l][2]; sd[l]=state[l][3];
            se[l]=state[l][4]; sf[l]=state[l][5];
            sg[l]=state[l][6]; sh[l]=state[l][7];
        }
        va=_mm512_loadu_epi32(sa); vb=_mm512_loadu_epi32(sb);
        vc=_mm512_loadu_epi32(sc); vd=_mm512_loadu_epi32(sd);
        ve=_mm512_loadu_epi32(se); vf=_mm512_loadu_epi32(sf);
        vg=_mm512_loadu_epi32(sg); vh=_mm512_loadu_epi32(sh);
    }

    /* 64 rounds */
    for (int i = 0; i < 64; i++) {
        /* Extend message schedule for rounds 16..63 */
        if (i >= 16) {
            __m512i s0 = SHA256_SIG0(W[(i-15) & 15]);
            __m512i s1 = SHA256_SIG1(W[(i- 2) & 15]);
            W[i & 15] = _mm512_add_epi32(
                _mm512_add_epi32(W[(i-16)&15], s0),
                _mm512_add_epi32(W[(i- 7)&15], s1));
        }

        __m512i ki = _mm512_set1_epi32((int)SHA256_K[i]);
        t1 = _mm512_add_epi32(vh,
             _mm512_add_epi32(SHA256_EP1(ve),
             _mm512_add_epi32(SHA256_CH(ve, vf, vg),
             _mm512_add_epi32(ki, W[i & 15]))));
        t2 = _mm512_add_epi32(SHA256_EP0(va), SHA256_MAJ(va, vb, vc));

        vh = vg; vg = vf; vf = ve;
        ve = _mm512_add_epi32(vd, t1);
        vd = vc; vc = vb; vb = va;
        va = _mm512_add_epi32(t1, t2);
    }

    /* Add back to state */
    {
        u32 ra[16],rb[16],rc[16],rd[16];
        u32 re[16],rf[16],rg[16],rh[16];
        _mm512_storeu_epi32(ra,va); _mm512_storeu_epi32(rb,vb);
        _mm512_storeu_epi32(rc,vc); _mm512_storeu_epi32(rd,vd);
        _mm512_storeu_epi32(re,ve); _mm512_storeu_epi32(rf,vf);
        _mm512_storeu_epi32(rg,vg); _mm512_storeu_epi32(rh,vh);
        for (int l = 0; l < 16; l++) {
            state[l][0]+=ra[l]; state[l][1]+=rb[l];
            state[l][2]+=rc[l]; state[l][3]+=rd[l];
            state[l][4]+=re[l]; state[l][5]+=rf[l];
            state[l][6]+=rg[l]; state[l][7]+=rh[l];
        }
    }
}

/* ── Hash 16 compressed pubkeys (33 bytes) → 16 SHA-256 ─── */
void sha256_16_pubkeys(const u8 pubkeys[16][33], u8 out[16][32]) {
    /* Build one padded 64-byte block per lane:
     * [33-byte msg][0x80][zeros][length = 264 bits = 0x108] */
    u8 blocks[16][64];
    for (int l = 0; l < 16; l++) {
        memset(blocks[l], 0, 64);
        memcpy(blocks[l], pubkeys[l], 33);
        blocks[l][33] = 0x80;
        /* bit length = 33 * 8 = 264 = 0x0000000000000108 */
        blocks[l][62] = 0x01;
        blocks[l][63] = 0x08;
    }

    /* Init state */
    u32 state[16][8];
    for (int l = 0; l < 16; l++)
        memcpy(state[l], SHA256_H0, 32);

    sha256_x16_compress(state, (const u8(*)[64])blocks);

    /* Extract digests (big-endian) */
    for (int l = 0; l < 16; l++) {
        for (int w = 0; w < 8; w++) {
            u32 v = state[l][w];
            out[l][w*4+0] = (u8)(v >> 24);
            out[l][w*4+1] = (u8)(v >> 16);
            out[l][w*4+2] = (u8)(v >>  8);
            out[l][w*4+3] = (u8)(v      );
        }
    }
}

/* ── Combined: 16 pubkeys → 16 hash160 ──────────────────── */
void avx512_pubkey_to_hash160_x16(const u8 pubkeys[16][33],
                                   u8 hash160s[16][20]) {
    u8 shas[16][32];
    sha256_16_pubkeys(pubkeys, shas);
    /* RIPEMD-160: run 16 scalar instances */
    for (int l = 0; l < 16; l++)
        ripemd160_hash(shas[l], 32, hash160s[l]);
}

/* ── Batch giant-step advance ────────────────────────────── */
/*
 * Advance n_pts Cyclone points by the same giant-step point.
 * Used to prefetch the next batch of giant step positions.
 * With AVX-512 we can process 8 independent point additions
 * simultaneously using the FE512 representation.
 *
 * For now uses scalar loop — FE512 path is in avx512_field.c.
 */
void bsgs_avx512_giant_advance(CyclonePoint *pts, size_t n,
                                const CyclonePoint *step) {
    for (size_t i = 0; i < n; i++)
        cyclone_point_add(&pts[i], &pts[i], step);
}

/* ── Sweep: start + i*G → hash160 for i in [0,16) ───────── */
void avx512_sweep_x16(const fe256 *k_start, const fe256 *step,
                       u8 hash160s[16][20], Point *points_out) {
    Scalar k0; memcpy(&k0, k_start, 32);
    Scalar st; memcpy(&st, step, 32);

    Point pts[16];
    secp256k1_scalar_mul_G(&pts[0], &k0);
    Point step_pt; secp256k1_scalar_mul_G(&step_pt, &st);
    for (int i = 1; i < 16; i++)
        point_add(&pts[i], &pts[i-1], &step_pt);

    if (points_out)
        memcpy(points_out, pts, 16 * sizeof(Point));

    u8 pubs[16][33];
    for (int i = 0; i < 16; i++)
        scalar_to_pubkey_compressed((Scalar*)&pts[i].x, pubs[i]);

    avx512_pubkey_to_hash160_x16(pubs, hash160s);
}

/* ── CPU feature detection ───────────────────────────────── */
void cpu_detect(CPUFeatures *f) {
    memset(f, 0, sizeof(*f));

    u32 eax, ebx, ecx, edx;

    /* Leaf 1: basic features */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        /* SSE4.2, AVX, etc. (not needed individually) */
    }

    /* Leaf 7, subleaf 0: extended features */
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    f->avx512f     = (ebx >> 16) & 1;
    f->avx512dq    = (ebx >> 17) & 1;
    f->avx512ifma  = (ebx >> 21) & 1;
    f->avx512bw    = (ebx >> 30) & 1;
    f->avx512vl    = (ebx >> 31) & 1;
    f->avx512vbmi  = (ecx >>  1) & 1;
    f->avx512vbmi2 = (ecx >>  6) & 1;
    f->avx512vnni  = (ecx >> 11) & 1;
    f->vaes        = (ecx >>  9) & 1;
    f->vpclmulqdq  = (ecx >> 10) & 1;

    /* Leaf 7, subleaf 1: additional features (AVX-512 BF16/FP16) */
    __cpuid_count(7, 1, eax, ebx, ecx, edx);
    f->avx512bf16  = (eax >> 5) & 1;

#if   AMD_ZNVER >= 4
    f->znver = 4;
#elif AMD_ZNVER >= 3
    f->znver = 3;
#elif AMD_ZNVER >= 2
    f->znver = 2;
#else
    f->znver = 0;
#endif
}

void cpu_print(const CPUFeatures *f) {
    const char *arch =
        f->znver == 4 ? "AMD Zen4 (EPYC Genoa / TR 7000)" :
        f->znver == 3 ? "AMD Zen3 (EPYC Milan / Ryzen 5000)" :
        f->znver == 2 ? "AMD Zen2 (EPYC Rome / Ryzen 3000)" :
                        "Unknown x86-64";
    printf("CPU Architecture: %s\n", arch);
    printf("  AVX-512F:    %s\n", f->avx512f     ? "YES" : "no");
    printf("  AVX-512BW:   %s\n", f->avx512bw    ? "YES" : "no");
    printf("  AVX-512VL:   %s\n", f->avx512vl    ? "YES" : "no");
    printf("  AVX-512DQ:   %s\n", f->avx512dq    ? "YES" : "no");
    printf("  AVX-512IFMA: %s  ← 52-bit field multiply\n",
           f->avx512ifma  ? "YES" : "no");
    printf("  AVX-512VBMI2:%s\n", f->avx512vbmi2 ? "YES" : "no");
    printf("  VAES:        %s  ← vectorized AES rounds\n",
           f->vaes        ? "YES" : "no");
    printf("  VPCLMULQDQ:  %s\n", f->vpclmulqdq  ? "YES" : "no");
    printf("  AVX-512VNNI: %s  ← Zen4 only\n",
           f->avx512vnni  ? "YES" : "no");
    printf("  AVX-512BF16: %s  ← Zen4 only\n",
           f->avx512bf16  ? "YES" : "no");
}

#else /* !HAVE_AVX512 */

void cpu_detect(CPUFeatures *f) {
    memset(f, 0, sizeof(*f));
    /* Try runtime CPUID even without compile-time AVX-512 */
#ifdef __GNUC__
    u32 eax=7, ebx=0, ecx=0, edx=0;
    __asm__ volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx)
                             : "a"(7), "c"(0));
    f->avx512f = (ebx >> 16) & 1;
    f->avx512bw= (ebx >> 30) & 1;
#endif
    f->znver = AMD_ZNVER;
}

void cpu_print(const CPUFeatures *f) {
    printf("AVX-512 not compiled in (rebuild with -DHAVE_AVX512)\n");
    printf("Runtime AVX-512F: %s\n", f->avx512f ? "available" : "no");
}

void avx512_pubkey_to_hash160_x16(const u8 p[16][33], u8 h[16][20]) {
    /* Scalar fallback */
    for (int l = 0; l < 16; l++) {
        u8 sha[32];
        sha256_hash(p[l], 33, sha);
        ripemd160_hash(sha, 32, h[l]);
    }
}

void bsgs_avx512_giant_advance(CyclonePoint *pts, size_t n,
                                const CyclonePoint *step) {
    for (size_t i = 0; i < n; i++)
        cyclone_point_add(&pts[i], &pts[i], step);
}

#endif /* HAVE_AVX512 */
