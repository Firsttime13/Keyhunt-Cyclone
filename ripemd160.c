/*============================================================
 * Keyhunt-Cyclone — src/ripemd160.c  (v2 — 2025)
 * RIPEMD-160 implementation
 * Standard reference: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 *============================================================*/

#include "common.h"
#include <string.h>

/* ── Rotation ────────────────────────────────────────────── */
#define ROL32(x,n) (((x)<<(n))|((x)>>(32-(n))))

/* ── Boolean functions (5 rounds) ───────────────────────── */
#define F1(x,y,z) ((x)^(y)^(z))
#define F2(x,y,z) (((x)&(y))|(~(x)&(z)))
#define F3(x,y,z) (((x)|(~(y)))^(z))
#define F4(x,y,z) (((x)&(z))|((y)&(~(z))))
#define F5(x,y,z) ((x)^((y)|(~(z))))

/* ── Round constants ─────────────────────────────────────── */
static const u32 KL[5] = {
    0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu
};
static const u32 KR[5] = {
    0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u
};

/* ── Message word selection (left and right rounds) ─────── */
static const u8 RL[80] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
     7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
     3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
     1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
     4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
};
static const u8 RR[80] = {
     5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
     6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
    15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
     8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
    12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
};

/* ── Shift amounts ───────────────────────────────────────── */
static const u8 SL[80] = {
    11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
    11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
    11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
     9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
};
static const u8 SR[80] = {
     8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
     9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
     9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
    15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
     8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
};

/* ── Compress one 64-byte block ──────────────────────────── */
static void rmd160_compress(u32 s[5], const u32 X[16]) {
    u32 al=s[0], bl=s[1], cl=s[2], dl=s[3], el=s[4];
    u32 ar=s[0], br=s[1], cr=s[2], dr=s[3], er=s[4];
    u32 t;

    for (int i = 0; i < 80; i++) {
        int round = i / 16;
        u32 fl, fr;

        switch (round) {
        case 0: fl = F1(bl,cl,dl); fr = F5(br,cr,dr); break;
        case 1: fl = F2(bl,cl,dl); fr = F4(br,cr,dr); break;
        case 2: fl = F3(bl,cl,dl); fr = F3(br,cr,dr); break;
        case 3: fl = F4(bl,cl,dl); fr = F2(br,cr,dr); break;
        default:fl = F5(bl,cl,dl); fr = F1(br,cr,dr); break;
        }

        /* Left round */
        t  = ROL32(al + fl + X[RL[i]] + KL[round], SL[i]) + el;
        al = el; el = dl; dl = ROL32(cl,10); cl = bl; bl = t;

        /* Right round */
        t  = ROL32(ar + fr + X[RR[i]] + KR[round], SR[i]) + er;
        ar = er; er = dr; dr = ROL32(cr,10); cr = br; br = t;
    }

    /* Combine */
    t    = s[1] + cl + dr;
    s[1] = s[2] + dl + er;
    s[2] = s[3] + el + ar;
    s[3] = s[4] + al + br;
    s[4] = s[0] + bl + cr;
    s[0] = t;
}

/* ── Public: hash arbitrary-length message ───────────────── */
void ripemd160_hash(const u8 *msg, size_t len, u8 digest[20]) {
    u32 state[5] = {
        0x67452301u, 0xEFCDAB89u, 0x98BADCFEu,
        0x10325476u, 0xC3D2E1F0u
    };

    u8  block[64];
    u32 X[16];
    size_t i = 0;

    /* Full 64-byte blocks */
    for (; i + 64 <= len; i += 64) {
        for (int j = 0; j < 16; j++) {
            const u8 *p = msg + i + j*4;
            X[j] = (u32)p[0] | ((u32)p[1]<<8)
                 | ((u32)p[2]<<16) | ((u32)p[3]<<24);
        }
        rmd160_compress(state, X);
    }

    /* Final block with padding */
    size_t rem = len - i;
    memcpy(block, msg + i, rem);
    block[rem++] = 0x80;

    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        for (int j=0;j<16;j++){
            const u8*p=block+j*4;
            X[j]=(u32)p[0]|((u32)p[1]<<8)|((u32)p[2]<<16)|((u32)p[3]<<24);
        }
        rmd160_compress(state, X);
        rem = 0;
    }

    memset(block + rem, 0, 56 - rem);

    /* Bit length (little-endian 64-bit for RIPEMD-160) */
    u64 bits = (u64)len * 8;
    for (int j = 0; j < 8; j++)
        block[56+j] = (u8)(bits >> (j*8));

    for (int j=0;j<16;j++){
        const u8*p=block+j*4;
        X[j]=(u32)p[0]|((u32)p[1]<<8)|((u32)p[2]<<16)|((u32)p[3]<<24);
    }
    rmd160_compress(state, X);

    /* Output (little-endian 32-bit words) */
    for (int j = 0; j < 5; j++) {
        digest[j*4+0] = (u8)(state[j]      );
        digest[j*4+1] = (u8)(state[j] >>  8);
        digest[j*4+2] = (u8)(state[j] >> 16);
        digest[j*4+3] = (u8)(state[j] >> 24);
    }
}
