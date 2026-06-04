# Baby-Step Giant-Step (BSGS) — Full Explanation (v2)

## Core Algorithm

Given a set of target public keys and a keyspace `[a, b]`, BSGS finds private key `k` such that `k*G = P`.

Choose `m = 2^bits` (baby step count).

**Baby steps** (precomputed once, stored in bloom/bP table):
```
For i = 0 to m-1:
    store hash160(i * G) → i
```

**Giant steps** (online search):
```
For j = 0, 1, 2, ...:
    Q_j = a*G + j*m*G
    For each target P_k:
        candidate = P_k - Q_j
        if hash160(candidate) in baby_table:
            key = a + baby_index + j*m
```

---

## Three-Tier Bloom Filter (v2)

Instead of a single bloom filter, v2 uses three cascaded levels plus an exact lookup table:

```
Input: hash160(candidate point)
         │
    ┌────▼────────────────────────────────────┐
    │  L1 Bloom (M elements × 256 sub-filters) │  ← indexed by hash160[0]
    │  FPR ≈ 0.001%                            │
    └────┬───────────────────────────────────── ┘
         │ pass (~0.001% false positives reach here)
    ┌────▼────────────────────────────────────┐
    │  L2 Bloom (M/32 elements × 256)         │
    │  FPR ≈ 0.001%                           │
    └────┬────────────────────────────────────┘
         │ pass (~1 in 10^6 reach here)
    ┌────▼────────────────────────────────────┐
    │  L3 Bloom (M/1024 elements × 256)       │
    │  FPR ≈ 0.0001%                          │
    └────┬────────────────────────────────────┘
         │ pass (~1 in 10^10 reach here)
    ┌────▼────────────────────────────────────┐
    │  bP Exact Table (sorted binary search)  │
    │  FPR = 0                                │
    └────┬────────────────────────────────────┘
         │
    KEY FOUND ✓
```

**Why 256 sub-filters?**
Hash160[0] (first byte) uniformly partitions keys into 256 buckets. Each sub-filter is 1/256 the size of the full filter, fitting entirely in L1 or L2 cache on EPYC 7773X (32 KB L1). This reduces cache misses by ~256×.

**Memory usage (bit-24, k=1):**
```
M = 2^24 = 16,777,216 entries
L1: 9.6 bits/entry × M       = ~20 MB
L2: 9.6 × M/32              = ~625 KB
L3: 9.6 × M/1024            = ~20 KB
bP: 8 bytes/entry × M/1024  = ~128 KB
Total: ~21 MB
```

---

## Grouped Modular Inverse (CPU_GRP_SIZE = 1024)

Computing `i*G` naively requires a field inversion per point addition (267 multiplications each). The grouped inverse trick batches 1024 consecutive additions:

```
For a batch of 1024 points P_0 .. P_1023:
    dx[i] = P_{i+1}.x - P_i.x      (1024 subtractions)
    batch_inv(dx, 1024)              (3×1023 muls + 1 inversion)
    recover individual lambdas       (1024 multiplications)
```

**Cost comparison:**
| Method | Field inversions | Muls per point |
|---|---|---|
| Naive (per point) | 1024 | ~267 |
| Grouped (batch-1024) | 1 | ~6 |
| Speedup | — | **~44×** |

---

## Point Negation Trick

For a baby step point `P = i*G`, its negation `-P = -i*G` costs nothing extra (just flip the y-coordinate sign). By inserting both `P` and `-P` into the bloom table at the same inverse computation step, we effectively double the number of baby steps covered per batch inversion call.

This means the effective baby-step coverage is `2*M` while the table only stores `M` distinct inverse computations.

---

## BSGS Submodes

| Submode | Strategy | Best for |
|---|---|---|
| `sequential` | j = 0, 1, 2, … (default) | Full range sweeps |
| `backward` | j = n, n-1, n-2, … | When key likely at end |
| `both` | Forward then backward | Covers both ends first |
| `random` | Shuffled j order | Uniform probability coverage |
| `dance` | First half forward, second half backward | Converges from both ends |
| `middleout` | Expands from midpoint outward | Key near range center |

**Choosing a submode:**
- No information about key location → `sequential` or `random`
- Key likely near a specific value → `middleout` centered there
- Collaborative multi-machine search → assign each machine a different submode

---

## k-Factor Scaling

The k-factor multiplies the baby-step count: `N = 2^bits × k`

With k=4, there are 4× more baby steps, so each giant step covers 4× more of the keyspace. The tradeoff is 4× RAM usage.

**Speed vs RAM tradeoff:**
| k | Baby steps (bits=24) | RAM | Giant steps for 2^64 range |
|---|---|---|---|
| 1 | 16M | ~21 MB | 1.1 trillion |
| 2 | 32M | ~42 MB | 549 billion |
| 4 | 64M | ~84 MB | 274 billion |
| 8 | 128M | ~168 MB | 137 billion |
| 16 | 256M | ~336 MB | 68 billion |

On EPYC 7773X with 768 MB 3D V-Cache, k=32 (512 MB bloom) fits entirely in L3, eliminating all RAM accesses for bloom lookups.

---

## Disk Persistence (-S flag)

The `-S` flag saves the bloom and bP tables to disk after the baby-step generation phase. On subsequent runs with `-S -6`:
- Bloom tables are loaded from disk (skipping baby-step generation entirely)
- `-6` skips XXH3 checksum verification (saves a few seconds)
- Baby-step generation for bit-24 at 128 threads takes ~30-60 seconds; loading takes ~2 seconds

**File naming convention (compatible with keyhunt):**
```
keyhunt_bsgs_4_<M>.blm   — L1 bloom
keyhunt_bsgs_6_<M>.blm   — L2 bloom
keyhunt_bsgs_7_<M>.blm   — L3 bloom
keyhunt_bsgs_2_<N>.tbl   — bP exact table (sorted)
```

---

## Range File (deep.txt)

The `-D FILE` flag reads keyspace ranges from a file (one `START:END` per line in hex). After each range is fully searched, it is marked as done in `checked-deep.txt`. Restarting the program with the same command automatically skips completed ranges.

**Example deep.txt:**
```
8000000000000000:9000000000000000
9000000000000000:A000000000000000
A000000000000000:FFFFFFFFFFFFFFFF
```

This is useful for:
- Collaborative searching (distribute ranges across machines)
- Checkpoint-based fault tolerance
- Systematic coverage of large keyspaces

---

## XXH3 Hashing

v2 replaces all internal hash functions (djb2, FNV) with XXH3:

| Function | Speed | FPR | Used for |
|---|---|---|---|
| djb2 (v1) | ~800 MB/s | — | Bloom key |
| XXH3 (v2) | ~25 GB/s | — | Bloom key, file checksum |

XXH3 is ~31× faster than djb2 for 20-byte inputs, directly reducing bloom lookup latency. On Zen4 with `XXH_ENABLE_AUTOVECTORIZE`, the compiler auto-vectorizes the mixing loop using AVX-512, giving further gains.

---

## Performance on Target Hardware

### EPYC 7773X (64c/128t, 768 MB L3)
- Baby step generation: ~60M steps/sec (128 threads + negation trick)
- Giant step throughput: ~14-20 Tkeys/s (bit-24, k=1, Cyclone EC)
- With k=4: ~56-80 Tkeys/s (if RAM allows full L3 coverage)

### Threadripper PRO 7000 (96c/192t, znver4)
- Baby step generation: ~90M steps/sec
- Giant step throughput: ~20-30 Tkeys/s
- AOCC 4.0 adds ~8-12% over GCC 13 on Zen4
