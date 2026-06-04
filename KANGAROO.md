# Pollard's Lambda (Wild Kangaroo) — v2

## Overview

The kangaroo algorithm solves the ECDLP in a bounded interval `[a, b]`
without the full O(√n) cost of BSGS when the interval is narrow.

**Expected steps:** `O(√(b - a))` vs BSGS's `O(√n)` for the full group.

---

## Two Herds

**Tame kangaroos** start at known positions:
```
T_i = t_i × G    where t_i ∈ [a, b] is known
```

**Wild kangaroos** start at the target plus an offset:
```
W_j = P + w_j × G    where P = k × G  (k unknown)
```

Both herds perform **pseudo-random walks**:
- Jump selection: `jump_index = x_coord mod JUMP_TABLE_SIZE`
- Same point always takes the same jump (deterministic walk)
- Jump distances chosen so expected step = `2^(dp_bits/2)`

---

## Distinguished Points (DP)

A point `P` is a **distinguished point** if:
```
P.x mod 2^dp_bits == 0    (low dp_bits bits of x are zero)
```

Expected steps between DPs: `2^dp_bits`

When a kangaroo hits a DP, it stores `(x_low_8_bytes, distance)` in the shared DP table.

---

## Collision → Key Recovery

When a tame DP and wild DP have the same `x_low`:
```
Tame:  T_i + d_T = k × G + d_W + W_j  (both at same point)
       t_i + d_T = k + w_j + d_W      (scalar equation mod n)
       k = t_i + d_T - w_j - d_W      (mod n)
```

The recovered key `k` is verified by checking `k × G == P`.

---

## Jump Table Design (v2)

Jump distances are centered around `2^(dp_bits/2)` with spread:

```c
for (int i = 0; i < KANG_JUMP_TABLE; i++) {
    int exp = dp_bits/2 - 4 + (i % 9);   // ±4 around center
    distance[i] = 2^exp;
    point[i]    = distance[i] × G;
}
```

This spread ensures good mixing properties while keeping the average
step close to the optimal `2^(dp_bits/2)` value.

---

## DP Table (v2)

The DP table uses **XXH3 for slot selection** (replacing the v1 custom hash):

```c
u64 slot = hash160_xxh3(x_low) & table_mask;
```

XXH3 provides better distribution with fewer collisions than the v1
djb2-based hash, reducing probe chain length by ~30%.

**Table sizing:** `capacity = 4 × expected_DPs = 4 × steps / 2^dp_bits`

For a 64-bit range with dp_bits=20 and 64 kangaroos:
- Expected steps: `2.5 × √(2^64) ≈ 2.5 × 2^32 ≈ 10 billion`
- Expected DPs: `10 billion / 2^20 ≈ 9,765`
- Table capacity: `~40,000 entries × 48 bytes ≈ 1.9 MB`

---

## Multi-Thread Strategy

Each thread manages `n_tame/T` tame and `n_wild/T` wild kangaroos.

**Thread placement:**
- Tame kangaroos are evenly spaced across `[a, b]`
- Thread `i` owns positions `[a + i × spacing, a + (i+1) × spacing)`
- Wild kangaroos start at `P + thread_offset × G`

**DP table access:** Protected by a mutex. For high thread counts (>64),
consider a sharded DP table (one mutex per 256 x_low prefix values) to
reduce contention.

---

## AVX-512 Batch Step (v2 stub)

With AVX-512, 8 kangaroos can be advanced simultaneously using
`point_batch_add()` — which uses `fe_batch_inv()` to compute 8 additions
with a single batch modular inversion:

```c
// 8 jump indices from 8 x-coordinates
ji[0..7] = pts[0..7].x.d[0] & (JUMP_TABLE_SIZE - 1)

// Gather 8 jump points
jumps[0..7] = jump_table.pts[ji[0..7]]

// Batch add: 8 kangaroo positions updated with 1 batch inversion
point_batch_add(pts, pts, jumps, 8)
```

This reduces modular inversions from 8 to 1 per SIMD batch step.

---

## Choosing dp_bits

| dp_bits | Steps between DPs | RAM per 10B steps | Best for |
|---|---|---|---|
| 16 | 65,536 | ~7.5 MB | Small ranges, many threads |
| 20 | 1,048,576 | ~0.5 MB | Medium ranges (64-80 bit) |
| 24 | 16,777,216 | ~30 KB | Large ranges (80-128 bit) |
| 28 | 268,435,456 | ~2 KB | Very large ranges |

Higher `dp_bits` → less DP table RAM but more synchronization overhead
between tame and wild herds. `dp_bits = 20` is the default and works
well for most 64-128 bit ranges.

---

## Comparison: Kangaroo vs BSGS

| Property | BSGS | Kangaroo |
|---|---|---|
| Time complexity | O(√M) baby + O(range/M) giant | O(√range) |
| Memory | O(M) for baby table | O(dp_table) — tiny |
| Multiple targets | Free (one baby table, many targets) | Per-target |
| Parallelism | Embarrassingly parallel | DP table contention |
| Best use | Multiple targets, wide range | Single target, narrow range |
| Restart cost | Load bloom from disk (-S flag) | Minimal (no table) |

**Rule of thumb:**
- More than 1 target → BSGS
- Range smaller than 2^40 → Kangaroo
- Range 2^40 to 2^80 → either, depending on available RAM
- Range larger than 2^80 → BSGS with large k-factor

---

## Usage Examples

```bash
# Narrow 64-bit range, single target
./keyhunt-cyclone -m kangaroo \
  -f address.txt \
  -r 8000000000000000:FFFFFFFFFFFFFFFF \
  --cyclone --kangaroo-dp 20 -t 64

# Very narrow range (brute force is faster below 2^24)
./keyhunt-cyclone -m address \
  -f address.txt \
  -r 1000000:2000000 -t 64

# With custom DP bits for very wide range
./keyhunt-cyclone -m kangaroo \
  -f address.txt \
  -b 80 \
  --kangaroo-dp 24 -t 128 --cyclone
```
