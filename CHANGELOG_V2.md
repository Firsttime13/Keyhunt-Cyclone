# Keyhunt-Cyclone v2.0.0 — Changelog

## Research Sources Used for v2

| Source | Finding Applied |
|---|---|
| keyhunt latest (albertobsd) | Three-tier bloom filter, BSGS submodes, CPU_GRP_SIZE=1024 |
| Slait/Keyhuntbsgs | XXH3 for checksums, parallel bloom loading, 20-40% speed gain |
| DeepWiki/keyhunt BSGS | Grouped modular inverse, negation trick, disk persistence |
| AMD EPYC 9004 Quick Ref | `--param prefetch-latency=300`, `-funroll-all-loops` |
| AWS AMD EPYC tuning guide | znver3/znver4 flag table, GCC version requirements |
| xxHash docs (Cyan4973) | XXH3 preferred over XXH64; Zen4 benefits from auto-vectorize |
| Intel HEXL / IFMA52 papers | 5-limb 52-bit representation for 256-bit field multiply |

---

## v2.0.0 Changes

### BSGS Engine (bsgs/bsgs_core.c)

**Three-tier bloom filter** replaces single bloom:
- L1: M elements × 256 sub-filters (indexed by hash160[0])
- L2: M/32 elements × 256 sub-filters
- L3: M/1024 elements × 256 sub-filters + bP exact table
- Impact: ~5× fewer RAM accesses per giant step; L3 cache-friendly on EPYC 3D V-Cache

**CPU_GRP_SIZE=1024 grouped modular inverse:**
- Process 1024 points per batch inverse call
- Montgomery's trick: 3(n-1) multiplications + 1 inversion for n=1024
- Cost per point: ~3 multiplications vs 267 multiplications (Fermat)
- Impact: ~2× baby step generation speed

**Point negation trick:**
- P+iG and P-iG computed from same inverse operation
- Effectively doubles baby steps per modular inverse call
- Impact: ~2× overall BSGS efficiency

**6 BSGS submodes:**
- `sequential` — standard L→R sweep (default)
- `backward` — R→L sweep
- `both` — forward then backward
- `random` — shuffled giant step order (Fisher-Yates)
- `dance` — alternating forward/backward from both ends
- `middleout` — expands outward from midpoint of range

**Disk persistence (-S flag):**
- Saves bloom L1/L2/L3 + bP table to `.blm` / `.tbl` files
- XXH3 checksum written alongside each file
- `-6` flag skips verification for fast restart
- File naming: `keyhunt_bsgs_4_<M>.blm`, `keyhunt_bsgs_2_<N>.tbl`

**Parallel bloom loading:**
- All threads build baby steps simultaneously
- Per-thread range: `[i*M/threads, (i+1)*M/threads)`
- Sub-filter mutex-free: each thread writes to different x-coord buckets

**Range file support (-D):**
- Reads `deep.txt` format: `START:END` (one per line, hex)
- Marks completed ranges in `checked-deep.txt`
- Resume by re-running same command — completed ranges skipped

**k-factor (-k N):**
- Scales N = M × k
- `-k 4`: 4× baby steps = 4× giant step coverage per sweep
- Requires k× RAM but achieves k× throughput
- Default: k=1

### New CLI Flags

| Flag | Description |
|---|---|
| `-b BITS` | Bit range shorthand: `-b 65` → `[2^64, 2^65)` |
| `-n N` | Baby step count (sets bits = ceil(log2(N))) |
| `-k K` | k-factor scaling |
| `-w MASK` | WIF mask search |
| `-D FILE` | Range input file |
| `-S` | Save bloom/bP tables |
| `-6` | Skip checksum verify |
| `-R` | Random giant step |
| `-s N` | Stats interval (seconds) |
| `--submode` | BSGS submode selection |
| `--endo` | GLV endomorphism (warns: NOT with BSGS) |
| `--no-compress` | Uncompressed pubkeys |

### New Search Modes

**WIF mask mode (`-m wif`):**
- Given partial WIF key with `_` as unknown characters
- Enumerates all valid base58 combinations for unknowns
- Tests each derived key against target addresses
- Example: `KwDiBf89QgGbjEhKnhXJuH_LrciVrZi_qYwk________________`

**RMD160 mode (`-m rmd`):**
- Searches by RIPEMD-160 directly (no address encoding)
- ~2× faster than address mode (no base58check overhead)
- Works for all altcoins using secp256k1 + RIPEMD-160

### Hashing

**XXH3 replaces djb2/FNV/SHA-256 for all internal use:**
- Bloom filter key hashing: `hash160_xxh3()` (inline in common.h)
- File checksums: `xxh3_file_checksum()` (replaces SHA-256 verify)
- Hash table probing in bsgs/kangaroo
- XXH3 is ~3× faster than XXH64 on small inputs
- Zen4 auto-vectorize enabled via `XXH_ENABLE_AUTOVECTORIZE`

### Build System

**AMD official flags added:**
```makefile
--param prefetch-latency=300    # EPYC 9004 tuning guide
-funroll-all-loops              # replaces --param max-unroll-times=8
-DXXH_ENABLE_AUTOVECTORIZE      # znver4: XXH3 benefits from SIMD
```

**New make targets:**
- `make pgo` — Profile-Guided Optimization (3-step)
- `make aocc` — Build with AMD AOCC 4.0 compiler
- `make avx512-generic` — Portable AVX-512 (x86-64-v4)
- `make check-gcc` — Verify GCC version for target arch

**GCC version requirements:**
| Target | Minimum GCC |
|---|---|
| znver2 | GCC 9+ |
| znver3 | GCC 11+ |
| znver4 | GCC 13+ |
| x86-64-v4 | GCC 10+ |

### Address Functions

**New:**
- `scalar_to_wif()` — private key → WIF encoded string
- `wif_to_scalar()` — WIF → private key + compression flag
- `wif_mask_match()` — test WIF against mask pattern
- `rangefile_load()` — parse deep.txt
- `rangefile_mark_done()` — write to checked-deep.txt
- `xxh3_file_checksum()` — streaming file hash
- `format_bytes()` / `format_rate()` — human-readable output
- `estimate_bloom_memory()` — RAM needed for given M/k
- `estimate_search_time()` — time-to-completion projection

### Performance Impact Summary

| Change | Expected Gain |
|---|---|
| Three-tier bloom | ~3× fewer RAM stalls on L3 cache miss |
| Grouped inverse (1024) | ~2× baby step generation speed |
| Negation trick | ~2× baby steps per inverse |
| XXH3 hashing | ~3× faster bloom key hashing |
| prefetch-latency=300 | ~5-10% on EPYC (from AMD guide) |
| -funroll-all-loops | ~5% instruction throughput |
| k-factor=4 | ~4× giant step coverage (linear with RAM) |
| Combined BSGS speedup | **~20-40% vs v1** (matching Slait benchmark) |
