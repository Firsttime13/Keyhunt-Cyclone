/*============================================================
 * Keyhunt-Cyclone — src/sha256.c  (v2 — 2025)
 * SHA-256 scalar implementation
 * Used as fallback when AVX-512 not available, and for
 * single-hash utility calls throughout the codebase.
 *============================================================*/

#include "common.h"
#include <string.h>

/* ── Round constants ─────────────────────────────────────── */
static const u32 K[64] = {
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

static const u32 H0[8] = {
    0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
    0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
};

/* ── Bit operations ──────────────────────────────────────── */
#define ROR32(x,n)  (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g)   (((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c)  (((a)&(b))^((a)&(c))^((b)&(c)))
#define EP0(x)      (ROR32(x, 2)^ROR32(x,13)^ROR32(x,22))
#define EP1(x)      (ROR32(x, 6)^ROR32(x,11)^ROR32(x,25))
#define SIG0(x)     (ROR32(x, 7)^ROR32(x,18)^((x)>> 3))
#define SIG1(x)     (ROR32(x,17)^ROR32(x,19)^((x)>>10))

/* ── Single block compression ────────────────────────────── */
static void sha256_block(u32 st[8], const u8 block[64]) {
    u32 W[64], a,b,c,d,e,f,g,h, t1,t2;

    for (int i = 0; i < 16; i++) {
        const u8 *p = block + i*4;
        W[i] = ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|(u32)p[3];
    }
    for (int i = 16; i < 64; i++)
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];

    a=st[0]; b=st[1]; c=st[2]; d=st[3];
    e=st[4]; f=st[5]; g=st[6]; h=st[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }

    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
    st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

/* ── Public: hash arbitrary-length message ───────────────── */
void sha256_hash(const u8 *msg, size_t len, u8 digest[32]) {
    u32 st[8];
    memcpy(st, H0, 32);
    u8 block[64];
    size_t i = 0;

    /* Full 64-byte blocks */
    for (; i + 64 <= len; i += 64)
        sha256_block(st, msg + i);

    /* Final partial block with padding */
    size_t rem = len - i;
    memcpy(block, msg + i, rem);
    block[rem++] = 0x80;

    if (rem > 56) {
        /* Need an extra block */
        memset(block + rem, 0, 64 - rem);
        sha256_block(st, block);
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);

    /* Append bit length (big-endian 64-bit) */
    u64 bits = (u64)len * 8;
    for (int j = 0; j < 8; j++)
        block[56+j] = (u8)(bits >> (56 - j*8));
    sha256_block(st, block);

    /* Output big-endian */
    for (int j = 0; j < 8; j++) {
        digest[j*4+0] = (u8)(st[j]>>24);
        digest[j*4+1] = (u8)(st[j]>>16);
        digest[j*4+2] = (u8)(st[j]>> 8);
        digest[j*4+3] = (u8)(st[j]    );
    }
}

/* ── Double SHA-256 (used in base58check) ────────────────── */
void sha256d_hash(const u8 *msg, size_t len, u8 digest[32]) {
    u8 tmp[32];
    sha256_hash(msg, len, tmp);
    sha256_hash(tmp, 32, digest);
}
