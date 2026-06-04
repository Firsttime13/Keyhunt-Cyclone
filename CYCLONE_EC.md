# Cyclone EC Integration (v2)

## What is Cyclone?

Cyclone is a high-performance EC arithmetic backend originally by Dookoo2.
It operates in **Montgomery form**, transforming field elements so that
modular reduction becomes a fast multiply-and-shift instead of a full division.

---

## Montgomery Form

A field element `a` is stored as `ã = a * R mod p` where:
- `p = 2^256 - 2^32 - 977`  (secp256k1 prime)
- `R = 2^256 mod p = 2^32 + 977 = 0x1000003D1`

Montgomery multiplication computes:
```
MonPro(ã, b̃) = ã × b̃ × R⁻¹  mod p
             = (a × b) × R    mod p   ← result stays in Montgomery form
```

No explicit modular reduction is needed inside the loop — only at conversion
boundaries. This is the key speed advantage.

---

## CIOS Algorithm (4-limb, 64-bit)

The implementation uses **Coarsely Integrated Operand Scanning**:

```
For i = 0 to 3:
    t += a × b[i]                      # 4 multiplications
    m = t[0] × p'  mod 2^64            # p' = -p^{-1} mod 2^64
    t += m × p                         # 4 multiplications
    t >>= 64                           # shift right one 64-bit word

if t >= p: t -= p                      # conditional final reduction
```

The constant `p' = 0xD838091DD2253531` is precomputed once for secp256k1.

**Cost per field multiplication:** ~8 64-bit multiplications + carries  
**vs naive schoolbook + Barrett:** ~16+ operations

---

## Point Formulas (Jacobian, a=0)

secp256k1 has `a = 0`, which eliminates one term from the standard
Weierstrass doubling formula. The Cyclone implementation uses:

### Doubling (dbl-2009-l)
```
A = X₁²
B = Y₁²
C = B²
D = 2 × ((X₁ + B)² - A - C)
E = 3A                          ← a=0 eliminates a×Z⁴ term
X₃ = E² - 2D
Y₃ = E×(D - X₃) - 8C
Z₃ = 2×Y₁×Z₁
```
Cost: 2M + 5S + 6add  
Reference: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

### Addition (add-2007-bl)
```
Z₁Z₁ = Z₁²,  Z₂Z₂ = Z₂²
U₁ = X₁×Z₂Z₂,  U₂ = X₂×Z₁Z₁
S₁ = Y₁×Z₂³,   S₂ = Y₂×Z₁³
H = U₂ - U₁
I = (2H)²
J = H×I
r = 2×(S₂ - S₁)
V = U₁×I
X₃ = r² - J - 2V
Y₃ = r×(V - X₃) - 2×S₁×J
Z₃ = ((Z₁+Z₂)² - Z₁Z₁ - Z₂Z₂) × H
```
Cost: 11M + 5S + 9add  
Reference: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl

---

## Fixed-Base Generator Table

Cyclone precomputes a windowed table for scalar multiplication with G:

```
CYCLONE_WINDOW_BITS = 6
CYCLONE_TABLE_STRIPES = ceil(256/6) = 43

Table[s][k] = k × (2^(s×6) × G)    for s=0..42, k=0..63
```

**Scalar multiplication cost:** 43 table lookups + ≤43 point additions  
vs naive double-and-add: 256 doublings + ~128 additions

**Table size:** 43 × 64 = 2752 points × 96 bytes/point ≈ 264 KB  
(fits in L2 cache on EPYC 7773X)

---

## GLV Endomorphism

secp256k1 has a special automorphism:
```
φ(x, y) = (β×x, y)
```
where `β` is a cube root of 1 modulo `p`:
```
β = 0x7AE96A2B657C0710A48CF03DDD99D63994C9A773FD44ECCEF9161ACD4D33
```

For any point `P`: `φ(P) = λ×P` where `λ` is a cube root of 1 mod `n`:
```
λ = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
```

This allows scalar decomposition: `k = k₁ + k₂×λ` with `|k₁|, |k₂| ≈ 128 bits`,
halving the number of EC doublings via Straus/Shamir simultaneous multi-scalar.

**Important:** GLV (`--endo`) is NOT compatible with BSGS mode. The baby-step
table is built assuming a specific relationship between baby indices and EC points.
The endomorphism changes this relationship, producing incorrect results.

---

## Performance vs Scalar Backend

| Operation | Scalar | Cyclone | Speedup |
|---|---|---|---|
| Field multiply | ~267 ops | ~8 ops | ~33× |
| Point double | ~10 field ops | ~8 field ops | ~1.25× |
| Point add | ~16 field ops | ~12 field ops | ~1.33× |
| Scalar mul G (fixed-base) | 256 dbl + 128 add | 43 lookups + 43 add | ~4× |
| Batch inv (1024 pts) | 1024 inv | 1 inv + 3072 mul | ~44× |

Combined effect on BSGS giant steps: **~40% faster** with `--cyclone`.

---

## Enabling Cyclone

```bash
# Single flag enables Montgomery backend:
./keyhunt-cyclone -m bsgs -f addr.txt -b 65 -t 128 --cyclone -S

# Verify it's active in verbose mode:
./keyhunt-cyclone -v ...
# Output: "Cyclone EC initialized  p'=0xD838091DD2253531"
```

Cyclone is automatically used for:
- Giant step point computation in BSGS
- Batch ladder in baby-step generation
- All scalar multiplications in kangaroo mode
