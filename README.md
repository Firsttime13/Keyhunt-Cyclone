# Keyhunt-Cyclone 🔑⚡  v2.0.0

> **High-performance secp256k1 private key search engine**
> Merged & updated: keyhunt · Cyclone · Keyhuntbsgs · binary_fuse_filter · cacachave · kangaroo-wild

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![AVX-512](https://img.shields.io/badge/AVX--512-IFMA52%20%7C%20VAES%20%7C%20VBMI2-green)]()
[![BSGS](https://img.shields.io/badge/BSGS-3--tier%20bloom%20%7C%206%20submodes-orange)]()
[![EPYC](https://img.shields.io/badge/AMD-EPYC%207773X%20%7C%20TR%207000-red)]()

---

## What's New in v2 (2025)

| Feature | Status |
|---|---|
| Three-tier bloom filter (L1/L2/L3 × 256 sub-filters) | ✅ New |
| XXH3 replaces SHA-256/djb2 for all internal hashing | ✅ New |
| 6 BSGS submodes: sequential/backward/both/random/dance/middleout | ✅ New |
| CPU_GRP_SIZE=1024 grouped modular inverse (2× baby step efficiency) | ✅ New |
| Point negation trick: P±iG computed per single inverse | ✅ New |
| Disk persistence of bloom/bP tables with XXH3 checksum (-S flag) | ✅ New |
| Parallel bloom filter loading across all threads | ✅ New |
| WIF mask search mode (-w KwDiBf89QgGb______) | ✅ New |
| Range file (deep.txt) + checkpoint tracking (-D flag) | ✅ New |
| k-factor RAM scaling (-k 4 = 4× baby steps, 4× speed) | ✅ New |
| -6 flag: skip XXH3 checksum (fast restart) | ✅ New |
| RMD160 mode: 2× faster than address mode | ✅ New |
| AOCC 4.0 compiler support (best Zen4 performance) | ✅ New |
| AMD official prefetch-latency=300 for EPYC 9004 | ✅ New |
| Profile-Guided Optimization (PGO) make target | ✅ New |
| NUMA-aware usage guide for multi-socket TR Pro | ✅ New |
| scalar_to_wif() / wif_to_scalar() | ✅ New |
| Full AVX-512 (IFMA52, VAES, VPCLMULQDQ, VBMI2) | ✅ Existing |
| Cyclone EC Montgomery arithmetic | ✅ Existing |
| Binary Fuse Filter 8/16-bit | ✅ Existing |
| Pollard's Lambda kangaroo | ✅ Existing |

---

## Repository Structure (v2)

```
Keyhunt-Cyclone/
├── src/
│   ├── main.c          — Entry point, all CLI flags (v2)
│   ├── keyhunt.c       — Mode runners, WIF, RMD, range file
│   ├── secp256k1.c     — EC: field arithmetic, batch inverse, NAF
│   ├── sha256.c        — SHA-256 scalar + double
│   ├── ripemd160.c     — RIPEMD-160
│   └── util.c          — XXH3 checksum, misc utilities
├── include/
│   ├── common.h        — Types, XXH3 inline, BSGS submodes enum
│   ├── secp256k1.h     — EC types and API
│   ├── cyclone.h       — Montgomery EC, GLV endomorphism
│   ├── bsgs.h          — Three-tier bloom, 6 submodes, bP table
│   ├── avx512_ec.h     — AVX-512 16-wide SHA-256, FE512 type
│   ├── binary_fuse.h   — BF8 / BF16 filter types
│   ├── kangaroo.h      — Pollard's Lambda types
│   └── keyhunt.h       — AppConfig v2, all mode prototypes
├── bsgs/
│   └── bsgs_core.c     — Full BSGS v2: 3-tier bloom, 6 submodes,
│                         grouped inverse, negation trick, disk persist
├── cyclone/
│   └── cyclone_ec.c    — Cyclone Montgomery EC + G-table
├── avx512/
│   └── avx512_sha256.c — 16-lane AVX-512 SHA-256, CPU detect
├── filter/
│   └── binary_fuse.c   — BF8 + BF16 populate/lookup/save/load
├── kangaroo/
│   └── kangaroo.c      — Wild kangaroo, DP table, multi-thread
├── tools/
│   ├── benchmark.c     — Full benchmark suite (v2)
│   └── gen_table.c     — Pre-compute BSGS tables
├── scripts/
│   ├── build_epyc.sh       — EPYC 7773X build (znver3)
│   └── build_threadripper.sh — Threadripper 7000 (znver4 + AOCC)
├── docs/
│   ├── BSGS_EXPLAINED.md   — Algorithm deep-dive
│   ├── CYCLONE_EC.md       — Montgomery arithmetic
│   ├── AVX512_NOTES.md     — IFMA52 field multiply
│   └── KANGAROO.md         — Pollard's Lambda
├── Makefile            — v2: PGO, AOCC, prefetch-latency=300
├── GITHUB_UPLOAD_GUIDE.md
├── LICENSE
└── README.md
```

---

## Build

### Quick (auto-detect CPU)
```bash
git clone https://github.com/Firsttime13/Keyhunt-Cyclone.git
cd Keyhunt-Cyclone
make -j$(nproc)
```

### EPYC 7773X (znver3 — requires GCC 11+)
```bash
./scripts/build_epyc.sh
# or:
make ARCH=znver3 -j$(nproc)
```

### Threadripper 7000 (znver4 — requires GCC 13+)
```bash
./scripts/build_threadripper.sh
# or:
make ARCH=znver4 -j$(nproc)
```

### With AOCC 4.0 (best Zen4 performance — download from developer.amd.com)
```bash
make aocc   # auto-uses clang from AOCC
```

### Profile-Guided Optimization (PGO — ~15% extra speed)
```bash
make pgo
./keyhunt-cyclone-pgo -m bsgs -f addr.txt -b 65 -t 128 --cyclone
```

### Benchmark first
```bash
make bench && ./benchmark
```

---

## Usage

### BSGS — primary mode

```bash
# Standard: bit-range 65, 128 threads, Cyclone EC, save tables
./keyhunt-cyclone -m bsgs -f addr.txt -b 65 -t 128 --cyclone -S -s 5

# With k-factor 4 (4× RAM = 4× speed for giant steps)
./keyhunt-cyclone -m bsgs -f addr.txt -b 65 -k 4 --cyclone -S

# Backward submode (right to left)
./keyhunt-cyclone -m bsgs -f addr.txt -b 65 --submode backward --cyclone

# Random submode
./keyhunt-cyclone -m bsgs -f addr.txt -b 65 --submode random -R

# Dance submode (forward then backward alternating)
./keyhunt-cyclone -m bsgs -f addr.txt -b 65 --submode dance --cyclone

# Middleout submode (expand from center)
./keyhunt-cyclone -m bsgs -f addr.txt -b 65 --submode middleout --cyclone

# From range file with checkpoint tracking
./keyhunt-cyclone -m bsgs -f addr.txt -b 65 -D deep.txt --cyclone -S

# Fast restart (skip XXH3 checksum, tables already verified)
./keyhunt-cyclone -m bsgs -f addr.txt -b 65 --cyclone -S -6

# Hex range (manual)
./keyhunt-cyclone -m bsgs -f addr.txt -r 8000000000000000:FFFFFFFFFFFFFFFF -t 128 --cyclone
```

### RMD160 mode (2× faster than address)
```bash
./keyhunt-cyclone -m rmd -f hashes.txt -r 1:FFFFFFFFFF -t 128 --cyclone
```

### WIF mask search
```bash
# Search for key matching known WIF characters (underscore = unknown)
./keyhunt-cyclone -m wif -f addr.txt \
  -w KwDiBf89QgGbjEhKnhXJuH_LrciVrZi_qYwk________________
```

### Kangaroo mode (narrow range)
```bash
./keyhunt-cyclone -m kangaroo -f addr.txt \
  -r 1000000000:2000000000 --cyclone --kangaroo-dp 20 -t 64
```

### Address mode
```bash
# Sequential with bfuse8 filter
./keyhunt-cyclone -m address -f addr.txt \
  -r 1:FFFFFFFFFFFFFFFFFFFF -t 128 --filter bfuse8

# Bech32 mode
./keyhunt-cyclone -m address -f addr.txt -b 65 --addr-type bech32 -t 128
```

### Vanity
```bash
./keyhunt-cyclone -m vanity --prefix 1Bitcoin -t 128 -o found.txt
```

---

## Full Flag Reference

| Flag | Description |
|---|---|
| `-m MODE` | address / bsgs / xpoint / rmd / vanity / kangaroo / wif |
| `-f FILE` | Address, pubkey, or hash160 target file |
| `-r START:END` | Hex keyspace range |
| `-b BITS` | Bit range: `-b 65` → `[2^64, 2^65)` |
| `-n N` | Baby step count (alternative to `-b`) |
| `-k K` | k-factor: N = 2^b × k (more RAM = more speed) |
| `-t N` | Thread count (default: all cores) |
| `-o FILE` | Append found keys to file |
| `-w MASK` | WIF mask (`_` = unknown character) |
| `-D FILE` | Range input file (default: `deep.txt`) |
| `-S` | Save bloom/bP tables to disk (fast restart) |
| `-6` | Skip XXH3 checksum verification |
| `-R` | Random giant step ordering |
| `-s N` | Stats output every N seconds (default: 10) |
| `-q` | Quiet mode |
| `-v` | Verbose |
| `--cyclone` | Enable Cyclone EC Montgomery backend |
| `--avx512` | Force AVX-512 (auto-detected) |
| `--endo` | GLV endomorphism (⚠️ NOT with BSGS!) |
| `--submode M` | sequential / backward / both / random / dance / middleout |
| `--filter TYPE` | bfuse8 / bfuse16 / bloom / none |
| `--addr-type T` | p2pkh / p2sh / bech32 |
| `--no-compress` | Uncompressed public keys |
| `--batch N` | Point batch size (default: 1024) |
| `--prefix P` | Vanity prefix |
| `--max N` | Stop after N found keys |
| `--kangaroo-dp N` | Distinguished point bits |

---

## Performance Reference

| Hardware | Mode | Speed |
|---|---|---|
| EPYC 7773X (64c, znver3) | BSGS sequential | ~14–20 Tkeys/s |
| EPYC 7773X (64c, znver3) | Address/RMD | ~500 Mkeys/s |
| Threadripper 7000 (96c, znver4) | BSGS sequential | ~20–30 Tkeys/s |
| Threadripper 7000 (96c, znver4) | Address/RMD | ~750 Mkeys/s |

Speed scales with:
- **k-factor**: `-k 4` gives ~4× giant step throughput (uses 4× RAM)
- **Cyclone EC**: ~40% faster point operations
- **AVX-512 IFMA52**: ~8× field multiplication throughput
- **Three-tier bloom**: Fewer RAM accesses per lookup vs single bloom

---

## BSGS Three-Tier Bloom Filter

The updated BSGS uses three cascaded bloom filters per lookup:

```
                    L1 bloom (M elements, 256 sub-filters)
                         │ ~99.999% reject non-matches
                    L2 bloom (M/32 elements)
                         │ ~99.999% reject L1 false positives
                    L3 bloom (M/1024 elements)
                         │ nearly zero false positives
                    bP exact table (binary search)
                         │ definitive match
                    KEY FOUND ✓
```

This means RAM bandwidth is only consumed for the rare candidates that pass all three filters. On EPYC 7773X with 768 MB 3D V-Cache, the entire L1+L2+L3 set fits in L3, yielding near-zero memory latency.

---

## deep.txt Range File Format

```
# One range per line: START:END (hex, no 0x prefix)
8000000000000000:9000000000000000
9000000000000000:A000000000000000
A000000000000000:B000000000000000
```

Progress is automatically saved to `checked-deep.txt` after each range completes. Resume by re-running the same command — completed ranges are skipped.

---

## License

MIT — see [LICENSE](LICENSE).

Credits: albertobsd, Dookoo2, Slait, punk-design, lmajowka, arulbero, xxHash (Cyan4973).
