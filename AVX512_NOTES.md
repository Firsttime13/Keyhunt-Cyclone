# AVX-512 Implementation Notes (v2)

## AMD Zen3 / Zen4 AVX-512 Architecture

### Why AMD AVX-512 Does Not Throttle

Intel AVX-512 implementations (Skylake-X, Ice Lake client) reduce clock frequency
when using 512-bit instructions because they implement AVX-512 with a single wide
execution unit. AMD's approach is different:

- **Zen3 (EPYC Milan / 7773X):** Two 256-bit FP/SIMD units fused per clock cycle to
  produce 512-bit throughput. No frequency penalty.
- **Zen4 (EPYC Genoa / TR 7000):** Native 512-bit units. Full throughput at boost
  frequency. Doubles integer throughput vs Zen3 for AVX-512IFMA workloads.

This means AVX-512 on AMD is always beneficial for compute-bound workloads like key
search, unlike Intel where the tradeoff depends on clock speed vs throughput.

---

## AVX-512 Extensions Used

### AVX-512F / BW / VL / DQ (baseline)
Always available when `__AVX512F__` is defined. Provides:
- 32 × 512-bit ZMM registers
- 64-bit mask registers (k0–k7)
- 8 × 64-bit or 16 × 32-bit SIMD arithmetic

### AVX-512IFMA — Integer Fused Multiply-Add (most important)
```
vpmadd52luq  zmm_dst, zmm_a, zmm_b   # low 52 bits of a*b + dst
vpmadd52huq  zmm_dst, zmm_a, zmm_b   # high 52 bits of a*b + dst
```
Each instruction performs 8 independent 52-bit × 52-bit multiply-accumulates
per clock cycle. This is the key instruction for secp256k1 field multiplication.

**5-limb 52-bit representation** for 256-bit field elements:
```
Field element a = a[0] + a[1]*2^52 + a[2]*2^104 + a[3]*2^156 + a[4]*2^208
where each a[i] fits in 52 bits (fits in a u64 with 12 bits headroom)
```
This allows 8 field multiplications per SIMD instruction, processing 8 different
EC points simultaneously. Throughput: ~8× scalar field multiply.

### AVX-512VBMI2 — Variable Bit Manipulation
```
vpshrdvq   # variable right-shift with concatenation
vpshldvq   # variable left-shift with concatenation
```
Used for efficient carry propagation in multi-precision arithmetic.
Saves ~2 instructions per carry step vs shift+or sequences.

### VAES — Vectorized AES
```
vaesenc zmm_state, zmm_state, zmm_rkey  # 4 AES rounds × 512 bits = 64 blocks
```
Used optionally for fast keyed hashing in bloom filter operations.
On Zen4, VAES throughput is 1 instruction per clock = 64 AES blocks per cycle.

### VPCLMULQDQ — Carry-less Multiply
```
vpclmulqdq zmm_dst, zmm_a, zmm_b, imm8
```
Used in Binary Fuse Filter hashing and CRC-based checksums.
Throughput: 1 per 2 clocks on Zen4, processing 8 × 64-bit operands.

---

## SHA-256 × 16 Parallel (AVX-512)

The `sha256_x16_compress()` function in `avx512/avx512_sha256.c` processes
**16 independent SHA-256 computations** in parallel using AVX-512's 16 × 32-bit
integer lanes per ZMM register.

### Key mappings:
```
zmm_a = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15]
```
Each `a_i` is the SHA-256 `a` state word for lane `i`. One ZMM instruction
updates all 16 lanes simultaneously.

### Critical operations use `ternarylogic`:
```c
/* CH(e,f,g) = (e AND f) XOR (NOT e AND g) */
SHA256_CH(e,f,g) = _mm512_ternarylogic_epi32(e, f, g, 0xCA)

/* MAJ(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c) */
SHA256_MAJ(a,b,c) = _mm512_ternarylogic_epi32(a, b, c, 0xE8)
```
`vpternlogd` computes any 3-input boolean function in one instruction.
This saves 2–3 instructions per round vs explicit AND/XOR/NOT sequences.

### Throughput (EPYC 7773X, 128 threads):
- Scalar SHA-256: ~50 Mhash/s per thread
- AVX-512 × 16:  ~800 Mhash/s per thread
- 128 threads:   ~100 Ghash/s total

---

## Batch Pipeline: pubkey → hash160

```
16 private keys
    │
    ▼  (8-bit window table lookup, no field arithmetic)
16 pubkeys (33 bytes each, compressed)
    │
    ▼  sha256_x16_compress()  [1 AVX-512 pass, 64 rounds × 16 lanes]
16 SHA-256 digests (32 bytes each)
    │
    ▼  ripemd160_hash() × 16  [scalar, ~16 ns each on Zen4]
16 hash160 values (20 bytes each)
    │
    ▼  bsgs_bloom_lookup() × 16
16 bloom results
```

The SHA-256 step is the bottleneck and is fully vectorized. RIPEMD-160 is not
easily vectorized due to its irregular round structure, but it is not the bottleneck
at current throughput levels.

---

## Compile Flags — Full Reference

### znver3 (EPYC 7773X, GCC 11+)
```makefile
-march=znver3 -mtune=znver3
-mavx512f -mavx512bw -mavx512vl -mavx512dq
-mavx512ifma -mavx512vbmi -mavx512vbmi2
-mvaes -mvpclmulqdq
-O3 -flto=auto -pipe
-funroll-all-loops
-fprefetch-loop-arrays
--param prefetch-latency=300          # AMD EPYC 9004 tuning guide
--param l1-cache-size=32
--param l2-cache-size=512
--param l3-cache-size=786432          # 768 MB 3D V-Cache
-fno-plt -fomit-frame-pointer
-DHAVE_AVX512 -DAMD_ZNVER=3
```

### znver4 (Threadripper 7000, GCC 13+)
```makefile
-march=znver4 -mtune=znver4
(all znver3 flags, plus:)
-mavx512vnni                          # Vector Neural Network Instructions
-mavx512bf16                          # BFloat16 arithmetic
-mavx512fp16                          # FP16 arithmetic (Zen4 only)
-DXXH_ENABLE_AUTOVECTORIZE            # XXH3 SIMD path
--param l2-cache-size=1024
--param l3-cache-size=1048576         # 1 GB L3 (Genoa-X)
-DAMD_ZNVER=4
```

### AOCC 4.0 (AMD Optimizing C Compiler — best Zen4)
```bash
# Download from developer.amd.com
aocc -march=znver4 -O3 -flto         # same flags, better auto-vectorization
# AOCC achieves ~8-12% better throughput vs GCC 13 on Zen4
# due to AMD-specific loop optimizations and register allocation
```

---

## Profile-Guided Optimization (PGO)

PGO can add 10–20% throughput on top of the static optimization flags:

```bash
# Step 1: instrument build
make pgo-gen

# Step 2: run training workload (10-30 seconds)
make pgo-train

# Step 3: use profile data
make pgo-use

# Or all in one:
make pgo
./keyhunt-cyclone-pgo -m bsgs -f addr.txt -b 65 -t 128 --cyclone -S
```

PGO is most effective when the training workload matches the target: use the same
address file and bit range you plan to search in production.
