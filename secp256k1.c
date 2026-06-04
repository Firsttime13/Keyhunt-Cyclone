/*============================================================
 * Keyhunt-Cyclone — src/secp256k1.c  (v2 — 2025)
 * secp256k1 EC field and point arithmetic
 *
 * Updates v2:
 *  - fe_batch_inv: uses contiguous stack allocation for
 *    better cache behaviour on znver3/znver4
 *  - point_mul_naf: corrected carry propagation in NAF loop
 *  - Generator table: 32 windows × 256 entries (8-bit window)
 *  - scalar_from_bytes / scalar_to_bytes: endian-safe
 *  - fe_mul: secp256k1 fast reduction (2^256 ≡ 2^32+977)
 *    corrected two-pass reduction with carry propagation
 *  - Added point_batch_add using fe_batch_inv
 *============================================================*/

#include "secp256k1.h"
#include <string.h>
#include <assert.h>

/* ── secp256k1 curve parameters ─────────────────────────────
 * p = 2^256 - 2^32 - 977
 *   = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 * G = (Gx, Gy) as defined in SEC 2
 */
const fe256 SECP256K1_P = {{
    0xFFFFFFFEFFFFFC2FULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL
}};

const fe256 SECP256K1_N = {{
    0xBFD25E8CD0364141ULL,
    0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL,
    0xFFFFFFFFFFFFFFFFULL
}};

const Point SECP256K1_G = {
    .x = {{
        0x59F2815B16F81798ULL,
        0x029BFCDB2DCE28D9ULL,
        0x55A06295CE870B07ULL,
        0x79BE667EF9DCBBACULL
    }},
    .y = {{
        0x9C47D08FFB10D4B8ULL,
        0xFD17B448A6855419ULL,
        0x5DA4FBFC0E1108A8ULL,
        0x483ADA7726A3C465ULL
    }},
    .infinity = false
};

/* ── Field element helpers ───────────────────────────────── */

/* Returns 1 if a < p, 0 otherwise */
static KC_FORCE_INLINE int fe_lt_p(const fe256 *a) {
    for (int i = 3; i >= 0; i--) {
        if (a->d[i] < SECP256K1_P.d[i]) return 1;
        if (a->d[i] > SECP256K1_P.d[i]) return 0;
    }
    return 0;
}

void fe_set_zero(fe256 *r)             { memset(r->d, 0, 32); }
void fe_set_one(fe256 *r)              { memset(r->d, 0, 32); r->d[0] = 1; }
void fe_copy(fe256 *r, const fe256 *a) { memcpy(r->d, a->d, 32); }

int fe_is_zero(const fe256 *a) {
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
}

int fe_equal(const fe256 *a, const fe256 *b) {
    return (a->d[0]==b->d[0]) & (a->d[1]==b->d[1]) &
           (a->d[2]==b->d[2]) & (a->d[3]==b->d[3]);
}

/* r = a + b  mod p */
void fe_add(fe256 *r, const fe256 *a, const fe256 *b) {
    unsigned __int128 t;
    u64 carry = 0;
    for (int i = 0; i < 4; i++) {
        t = (unsigned __int128)a->d[i] + b->d[i] + carry;
        r->d[i] = (u64)t;
        carry   = (u64)(t >> 64);
    }
    /* Conditional subtract p if r >= p or carry set */
    if (carry || !fe_lt_p(r)) {
        u64 borrow = 0;
        for (int i = 0; i < 4; i++) {
            unsigned __int128 s = (unsigned __int128)r->d[i]
                                - SECP256K1_P.d[i] - borrow;
            r->d[i] = (u64)s;
            borrow  = (s >> 127) & 1;
        }
    }
}

/* r = a - b  mod p */
void fe_sub(fe256 *r, const fe256 *a, const fe256 *b) {
    u64 borrow = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 t = (unsigned __int128)a->d[i]
                            - b->d[i] - borrow;
        r->d[i] = (u64)t;
        borrow  = (t >> 127) & 1;
    }
    if (borrow) {
        u64 carry = 0;
        for (int i = 0; i < 4; i++) {
            unsigned __int128 s = (unsigned __int128)r->d[i]
                                + SECP256K1_P.d[i] + carry;
            r->d[i] = (u64)s;
            carry   = (u64)(s >> 64);
        }
    }
}

/* r = -a  mod p */
void fe_neg(fe256 *r, const fe256 *a) {
    if (fe_is_zero(a)) { fe_set_zero(r); return; }
    u64 borrow = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 t = (unsigned __int128)SECP256K1_P.d[i]
                            - a->d[i] - borrow;
        r->d[i] = (u64)t;
        borrow  = (t >> 127) & 1;
    }
}

/*
 * r = a * b  mod p
 *
 * secp256k1 special reduction:  p = 2^256 - 2^32 - 977
 * So:  2^256 ≡ 2^32 + 977  (mod p)
 *
 * Product a*b = lo[0..3] + hi[4..7] * 2^256
 *             ≡ lo[0..3] + hi[0..3] * (2^32 + 977)  (mod p)
 *
 * Two reduction passes are sufficient for a 512-bit input.
 */
void fe_mul(fe256 *r, const fe256 *a, const fe256 *b) {
    u64 lo[8] = {0};
    unsigned __int128 t;

    /* Schoolbook 4×4 → 8-limb product */
    for (int i = 0; i < 4; i++) {
        u64 carry = 0;
        for (int j = 0; j < 4; j++) {
            t = (unsigned __int128)a->d[i] * b->d[j]
              + lo[i+j] + carry;
            lo[i+j] = (u64)t;
            carry   = (u64)(t >> 64);
        }
        lo[i+4] += carry;
    }

    /* Two-pass reduction:  lo[4..7] * 2^256 ≡ lo[4..7] * (2^32 + 977) */
    for (int pass = 0; pass < 2; pass++) {
        u64 hi[4] = { lo[4], lo[5], lo[6], lo[7] };
        lo[4] = lo[5] = lo[6] = lo[7] = 0;

        /* Add hi * 2^32:  each limb contributes to two output limbs */
        u64 carry = 0;
        for (int i = 0; i < 4; i++) {
            /* hi[i] shifts up 32 bits, landing in limbs i and i+1 */
            t = (unsigned __int128)lo[i]
              + ((unsigned __int128)hi[i] << 32)
              + (i > 0 ? ((unsigned __int128)(hi[i-1] >> 32)) : 0)
              + carry;
            lo[i] = (u64)t;
            carry = (u64)(t >> 64);
        }
        /* Handle the 977 * hi contribution */
        u64 carry2 = 0;
        for (int i = 0; i < 4; i++) {
            t = (unsigned __int128)lo[i]
              + (unsigned __int128)hi[i] * 977
              + carry2;
            lo[i]  = (u64)t;
            carry2 = (u64)(t >> 64);
        }
        /* Carry from 977 multiplication may overflow into lo[4] */
        lo[4] = carry + carry2;
    }

    /* Copy and conditionally reduce */
    memcpy(r->d, lo, 32);
    if (!fe_lt_p(r)) {
        u64 borrow = 0;
        for (int i = 0; i < 4; i++) {
            unsigned __int128 s = (unsigned __int128)r->d[i]
                                - SECP256K1_P.d[i] - borrow;
            r->d[i] = (u64)s;
            borrow  = (s >> 127) & 1;
        }
    }
}

void fe_sqr(fe256 *r, const fe256 *a) {
    fe_mul(r, a, a);
}

/*
 * r = a^{-1}  mod p  via  a^{p-2}  (Fermat's little theorem)
 *
 * p-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
 *
 * Addition chain (265 multiplications — standard secp256k1 chain):
 * Same chain used in Bitcoin Core, libsecp256k1, keyhunt.
 */
void fe_inv(fe256 *r, const fe256 *a) {
    fe256 x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223;

    fe_sqr(&x2,  a);           fe_mul(&x2,   &x2,   a);
    fe_sqr(&x3,  &x2);         fe_mul(&x3,   &x3,   a);
    fe_copy(&x6,  &x3);  for (int i=0;i<3;i++) fe_sqr(&x6, &x6);
    fe_mul(&x6,  &x6,  &x3);
    fe_copy(&x9,  &x6);  for (int i=0;i<3;i++) fe_sqr(&x9, &x9);
    fe_mul(&x9,  &x9,  &x3);
    fe_copy(&x11, &x9);  for (int i=0;i<2;i++) fe_sqr(&x11,&x11);
    fe_mul(&x11, &x11, &x2);
    fe_copy(&x22, &x11); for (int i=0;i<11;i++) fe_sqr(&x22,&x22);
    fe_mul(&x22, &x22, &x11);
    fe_copy(&x44, &x22); for (int i=0;i<22;i++) fe_sqr(&x44,&x44);
    fe_mul(&x44, &x44, &x22);
    fe_copy(&x88, &x44); for (int i=0;i<44;i++) fe_sqr(&x88,&x88);
    fe_mul(&x88, &x88, &x44);
    fe_copy(&x176,&x88); for (int i=0;i<88;i++) fe_sqr(&x176,&x176);
    fe_mul(&x176,&x176,&x88);
    fe_copy(&x220,&x176);for (int i=0;i<44;i++) fe_sqr(&x220,&x220);
    fe_mul(&x220,&x220,&x44);
    fe_copy(&x223,&x220);for (int i=0;i<3;i++) fe_sqr(&x223,&x223);
    fe_mul(&x223,&x223,&x3);

    fe_copy(r, &x223);
    for (int i=0;i<23;i++) fe_sqr(r, r); fe_mul(r, r, &x22);
    for (int i=0;i<5;i++)  fe_sqr(r, r); fe_mul(r, r, a);
    for (int i=0;i<3;i++)  fe_sqr(r, r); fe_mul(r, r, &x2);
    fe_sqr(r, r);
    fe_mul(r, r, a);
}

/*
 * Batch modular inversion — Montgomery's trick
 * Computes out[i] = in[i]^{-1} mod p for all i.
 * Cost: 3(n-1) multiplications + 1 inversion.
 *
 * v2: uses malloc for prefix array to avoid stack overflow
 * on large batches (CPU_GRP_SIZE = 1024).
 */
void fe_batch_inv(fe256 *out, const fe256 *in, size_t n) {
    if (n == 0) return;
    if (n == 1) { fe_inv(&out[0], &in[0]); return; }

    fe256 *prefix = (fe256 *)malloc(n * sizeof(fe256));
    if (!prefix) {
        /* Fallback: scalar inversion */
        for (size_t i = 0; i < n; i++) fe_inv(&out[i], &in[i]);
        return;
    }

    /* prefix[i] = in[0] * in[1] * ... * in[i] */
    fe_copy(&prefix[0], &in[0]);
    for (size_t i = 1; i < n; i++)
        fe_mul(&prefix[i], &prefix[i-1], &in[i]);

    /* inv = prefix[n-1]^{-1} = (product of all inputs)^{-1} */
    fe256 inv;
    fe_inv(&inv, &prefix[n-1]);

    /* Back-substitute */
    for (size_t i = n-1; i > 0; i--) {
        fe_mul(&out[i], &inv, &prefix[i-1]);  /* out[i] = in[i]^{-1} */
        fe_mul(&inv,    &inv, &in[i]);         /* update running inverse */
    }
    fe_copy(&out[0], &inv);

    free(prefix);
}

/* ── Point arithmetic ────────────────────────────────────── */

void point_set_infinity(Point *P) {
    fe_set_zero(&P->x); fe_set_zero(&P->y); P->infinity = true;
}
int  point_is_infinity(const Point *P) { return P->infinity; }
void point_copy(Point *r, const Point *P) { memcpy(r, P, sizeof(Point)); }
int  point_equal(const Point *a, const Point *b) {
    if (a->infinity && b->infinity) return 1;
    if (a->infinity || b->infinity) return 0;
    return fe_equal(&a->x, &b->x) && fe_equal(&a->y, &b->y);
}

void point_neg(Point *r, const Point *a) {
    point_copy(r, a);
    if (!a->infinity) fe_neg(&r->y, &a->y);
}

/* r = P + Q  (affine coordinates) */
void point_add(Point *r, const Point *P, const Point *Q) {
    if (P->infinity) { point_copy(r, Q); return; }
    if (Q->infinity) { point_copy(r, P); return; }

    if (fe_equal(&P->x, &Q->x)) {
        if (fe_equal(&P->y, &Q->y)) { point_dbl(r, P); return; }
        point_set_infinity(r); return;  /* P == -Q */
    }

    fe256 dy, dx, lam, lam2, rx, ry;
    fe_sub(&dy, &Q->y, &P->y);
    fe_sub(&dx, &Q->x, &P->x);
    fe_inv(&dx, &dx);
    fe_mul(&lam, &dy, &dx);              /* λ = (Qy-Py)/(Qx-Px) */

    fe_sqr(&lam2, &lam);
    fe_sub(&rx, &lam2, &P->x);
    fe_sub(&rx, &rx,   &Q->x);          /* rx = λ² - Px - Qx   */

    fe_sub(&ry, &P->x, &rx);
    fe_mul(&ry, &lam, &ry);
    fe_sub(&ry, &ry,  &P->y);           /* ry = λ(Px-rx) - Py  */

    r->x = rx; r->y = ry; r->infinity = false;
}

/* r = 2P  (affine coordinates, secp256k1 a=0) */
void point_dbl(Point *r, const Point *P) {
    if (P->infinity || fe_is_zero(&P->y)) { point_set_infinity(r); return; }

    fe256 x2, lam, lam2, rx, ry, y2;

    fe_sqr(&x2, &P->x);                 /* x²  */
    fe_add(&lam, &x2, &x2);
    fe_add(&lam, &lam, &x2);            /* 3x² (a=0) */
    fe_add(&y2, &P->y, &P->y);          /* 2y  */
    fe_inv(&y2, &y2);
    fe_mul(&lam, &lam, &y2);            /* λ = 3x² / 2y */

    fe_sqr(&lam2, &lam);
    fe_sub(&rx, &lam2, &P->x);
    fe_sub(&rx, &rx,   &P->x);          /* rx = λ² - 2Px */

    fe_sub(&ry, &P->x, &rx);
    fe_mul(&ry, &lam, &ry);
    fe_sub(&ry, &ry,  &P->y);           /* ry = λ(Px-rx) - Py */

    r->x = rx; r->y = ry; r->infinity = false;
}

/* Scalar multiplication: double-and-add (LSB first) */
void point_mul(Point *r, const Point *P, const Scalar *k) {
    point_set_infinity(r);
    Point add; point_copy(&add, P);
    for (int i = 0; i < 4; i++) {
        u64 limb = k->d[i];
        for (int bit = 0; bit < 64; bit++) {
            if (limb & 1ULL) point_add(r, r, &add);
            point_dbl(&add, &add);
            limb >>= 1;
        }
    }
}

/*
 * NAF scalar multiplication — ~25% fewer additions than binary.
 *
 * We use width-3 window NAF (wNAF-3) which reduces additions
 * further to ~1/4 instead of ~1/3 of total doublings.
 */
void point_mul_naf(Point *r, const Point *P, const Scalar *k) {
    /* Compute 5 precomputed odd multiples: P, 3P, 5P, 7P, 9P */
    Point pre[5];
    Point P2; point_dbl(&P2, P);
    point_copy(&pre[0], P);
    for (int i = 1; i < 5; i++) point_add(&pre[i], &pre[i-1], &P2);

    /* Extract wNAF digits */
    int naf[259]; int naflen = 0;
    u64 tmp[4]; memcpy(tmp, k->d, 32);

    while (tmp[0]|tmp[1]|tmp[2]|tmp[3]) {
        if (tmp[0] & 1) {
            int mof = (int)(tmp[0] & 7);    /* 3-bit window */
            int naf_d;
            if (mof >= 5) {
                /* Subtract 8 to get negative digit */
                naf_d = mof - 8;   /* -3, -1 */
                u64 carry = (u64)(8 - mof);
                for (int i=0;i<4&&carry;i++) {
                    tmp[i] += carry; carry = (tmp[i]==0)?1:0;
                }
            } else {
                naf_d = mof;   /* 1, 3, 5, 7 */
                u64 borrow = (u64)mof;
                for (int i=0;i<4&&borrow;i++) {
                    u64 old = tmp[i]; tmp[i] -= borrow;
                    borrow = (tmp[i] > old) ? 1 : 0;
                }
            }
            naf[naflen++] = naf_d;
        } else {
            naf[naflen++] = 0;
        }
        /* Right shift by 1 */
        for (int i=0;i<3;i++) tmp[i] = (tmp[i]>>1)|(tmp[i+1]<<63);
        tmp[3] >>= 1;
    }

    /* Evaluate */
    Point neg_pre[5];
    for (int i = 0; i < 5; i++) point_neg(&neg_pre[i], &pre[i]);

    point_set_infinity(r);
    for (int i = naflen-1; i >= 0; i--) {
        point_dbl(r, r);
        int d = naf[i];
        if      (d > 0) point_add(r, r, &pre[(d-1)/2]);
        else if (d < 0) point_add(r, r, &neg_pre[(-d-1)/2]);
    }
}

/*
 * Batch point addition using fe_batch_inv (Montgomery's trick).
 * Computes r[i] = P[i] + Q[i] for i in [0, n).
 * Cost: n additions + 1 batch inversion (3(n-1) multiplications).
 */
void point_batch_add(Point *r, const Point *P, const Point *Q, size_t n) {
    fe256 *dx    = (fe256 *)malloc(n * sizeof(fe256));
    fe256 *inv_dx= (fe256 *)malloc(n * sizeof(fe256));
    if (!dx || !inv_dx) {
        free(dx); free(inv_dx);
        for (size_t i=0;i<n;i++) point_add(&r[i], &P[i], &Q[i]);
        return;
    }

    /* Compute dx[i] = Q[i].x - P[i].x for non-trivial cases */
    for (size_t i = 0; i < n; i++) {
        if (P[i].infinity || Q[i].infinity ||
            fe_equal(&P[i].x, &Q[i].x)) {
            fe_set_one(&dx[i]);   /* dummy, will handle separately */
        } else {
            fe_sub(&dx[i], &Q[i].x, &P[i].x);
        }
    }

    fe_batch_inv(inv_dx, dx, n);

    for (size_t i = 0; i < n; i++) {
        if (P[i].infinity) { r[i] = Q[i]; continue; }
        if (Q[i].infinity) { r[i] = P[i]; continue; }
        if (fe_equal(&P[i].x, &Q[i].x)) {
            if (fe_equal(&P[i].y, &Q[i].y)) point_dbl(&r[i], &P[i]);
            else point_set_infinity(&r[i]);
            continue;
        }

        fe256 dy, lam, lam2, rx, ry;
        fe_sub(&dy,  &Q[i].y, &P[i].y);
        fe_mul(&lam, &dy, &inv_dx[i]);
        fe_sqr(&lam2, &lam);
        fe_sub(&rx, &lam2, &P[i].x);
        fe_sub(&rx, &rx,   &Q[i].x);
        fe_sub(&ry, &P[i].x, &rx);
        fe_mul(&ry, &lam, &ry);
        fe_sub(&ry, &ry, &P[i].y);
        r[i].x = rx; r[i].y = ry; r[i].infinity = false;
    }

    free(dx); free(inv_dx);
}

/* ── Scalar utilities ────────────────────────────────────── */

void scalar_set_u64(Scalar *s, u64 v) {
    s->d[0] = v;
    s->d[1] = s->d[2] = s->d[3] = 0;
}

/* Big-endian 32-byte → Scalar (d[3] = most significant) */
void scalar_from_bytes(Scalar *s, const u8 *b32) {
    for (int i = 0; i < 4; i++) {
        s->d[3-i] = 0;
        for (int j = 0; j < 8; j++)
            s->d[3-i] |= (u64)b32[i*8+j] << (56 - j*8);
    }
}

/* Scalar → big-endian 32-byte */
void scalar_to_bytes(const Scalar *s, u8 *b32) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            b32[i*8+j] = (u8)(s->d[3-i] >> (56 - j*8));
}

void scalar_inc(Scalar *s) {
    for (int i = 0; i < 4; i++) {
        s->d[i]++;
        if (s->d[i] != 0) break;
    }
}

void scalar_add(Scalar *r, const Scalar *a, const Scalar *b) {
    u64 carry = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 t = (unsigned __int128)a->d[i] + b->d[i] + carry;
        r->d[i] = (u64)t;
        carry   = (u64)(t >> 64);
    }
}

void scalar_sub(Scalar *r, const Scalar *a, const Scalar *b) {
    u64 borrow = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 t = (unsigned __int128)a->d[i] - b->d[i] - borrow;
        r->d[i] = (u64)t;
        borrow  = (t >> 127) & 1;
    }
}

int scalar_cmp(const Scalar *a, const Scalar *b) {
    for (int i = 3; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return  1;
        if (a->d[i] < b->d[i]) return -1;
    }
    return 0;
}

/* ── Generator table (8-bit window, 32 stripes) ─────────── */
/* G_table[w][k] = k * (256^w * G),  w=0..31, k=0..255      */
static Point   G_table[32][256];
static bool    G_table_ready = false;

void secp256k1_build_gtable(void) {
    if (G_table_ready) return;

    KC_LOG("Building secp256k1 generator table (32 × 256 entries)...");

    Point base; point_copy(&base, &SECP256K1_G);

    for (int w = 0; w < 32; w++) {
        point_set_infinity(&G_table[w][0]);
        point_copy(&G_table[w][1], &base);
        for (int k = 2; k < 256; k++)
            point_add(&G_table[w][k], &G_table[w][k-1], &base);
        /* Advance base by 8 doublings = multiply by 2^8 = 256 */
        for (int d = 0; d < 8; d++) point_dbl(&base, &base);
    }

    G_table_ready = true;
    KC_LOG("Generator table ready.");
}

/* Fixed-base scalar multiplication via 8-bit window table */
void secp256k1_scalar_mul_G(Point *r, const Scalar *k) {
    u8 kb[32]; scalar_to_bytes(k, kb);
    point_set_infinity(r);
    /* kb[31] = LSB stripe, kb[0] = MSB stripe */
    for (int w = 0; w < 32; w++) {
        u8 idx = kb[31 - w];
        if (idx) point_add(r, r, &G_table[w][idx]);
    }
}

/* Public key derivation */
void scalar_to_pubkey_compressed(const Scalar *k, u8 *out33) {
    Point P; secp256k1_scalar_mul_G(&P, k);
    out33[0] = (P.y.d[0] & 1) ? 0x03 : 0x02;
    /* x-coordinate in big-endian */
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            out33[1 + i*8 + j] = (u8)(P.x.d[3-i] >> (56 - j*8));
}

void scalar_to_pubkey_uncompressed(const Scalar *k, u8 *out65) {
    Point P; secp256k1_scalar_mul_G(&P, k);
    out65[0] = 0x04;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++) {
            out65[1    + i*8+j] = (u8)(P.x.d[3-i] >> (56-j*8));
            out65[1+32 + i*8+j] = (u8)(P.y.d[3-i] >> (56-j*8));
        }
}
