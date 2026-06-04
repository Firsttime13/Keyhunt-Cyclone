#!/usr/bin/env bash
##############################################################
# Keyhunt-Cyclone — scripts/build_threadripper.sh  (v2 — 2025)
# Optimized build for AMD Threadripper PRO 7000 (Genoa-X, znver4)
# 96 cores / 192 threads / AVX-512 + VNNI + BF16
#
# Option A: GCC 13+ (mainstream)
# Option B: AOCC 4.0 (AMD's own compiler — best Zen4 tuning)
#
# Flags from AMD EPYC 9004 Compiler Options Quick Reference Guide
##############################################################

set -euo pipefail

echo "======================================================"
echo "  Keyhunt-Cyclone v2 — Threadripper 7000 Build"
echo "  Target: znver4 + AVX-512 + VNNI + BF16 + FP16"
echo "======================================================"

# ── Detect compiler preference ────────────────────────────
USE_AOCC=0
if command -v aocc &>/dev/null; then
    USE_AOCC=1
    echo "✓ AOCC detected — will use AMD Optimizing C/C++ Compiler"
    AOCC_VER=$(aocc --version 2>&1 | head -1)
    echo "  $AOCC_VER"
else
    echo "  AOCC not found — using GCC"
    echo "  (Download AOCC 4.0+ from developer.amd.com for best Zen4 perf)"
fi

# ── GCC version check ─────────────────────────────────────
GCC_VER=$(gcc -dumpversion | cut -d. -f1)
echo "GCC version: $GCC_VER"
if [ "$USE_AOCC" -eq 0 ] && [ "$GCC_VER" -lt 13 ]; then
    echo "WARNING: GCC $GCC_VER < 13. znver4 officially requires GCC 13+."
    echo "Attempting build anyway — some znver4 flags may be ignored."
fi

# ── Dependency check ──────────────────────────────────────
if ! ldconfig -p 2>/dev/null | grep -q libgmp; then
    echo "Installing libgmp-dev..."
    sudo apt-get install -y libgmp-dev 2>/dev/null || \
    sudo dnf install -y gmp-devel 2>/dev/null || true
fi
echo "✓ libgmp OK"

# ── NUMA topology info ────────────────────────────────────
if command -v numactl &>/dev/null; then
    echo ""
    echo "NUMA topology:"
    numactl --hardware | head -8
    echo ""
fi

# ── Build ─────────────────────────────────────────────────
make clean

if [ "$USE_AOCC" -eq 1 ]; then
    echo "Building with AOCC 4.0 (znver4 + full AVX-512)..."
    make CC=aocc ARCH=znver4 -j$(nproc) 2>&1 | tee /tmp/build_tr7000.log
else
    echo "Building with GCC (znver4 + full AVX-512)..."
    echo "  --param prefetch-latency=300 (AMD official tuning)"
    echo "  -funroll-all-loops"
    echo "  XXH_ENABLE_AUTOVECTORIZE (Zen4 benefits per xxHash docs)"
    make ARCH=znver4 -j$(nproc) 2>&1 | tee /tmp/build_tr7000.log
fi

echo ""
if [ -f keyhunt-cyclone ]; then
    SIZE=$(du -h keyhunt-cyclone | cut -f1)
    echo "======================================================"
    echo "  ✅  BUILD SUCCESS: ./keyhunt-cyclone  ($SIZE)"
    echo "======================================================"
    echo ""
    echo "  Recommended BSGS run (192 threads, bit-range 65):"
    echo "  ./keyhunt-cyclone -m bsgs -f addresses.txt -b 65 \\"
    echo "    -t 192 -k 4 --cyclone -S -s 5 --submode sequential"
    echo ""
    echo "  With NUMA pinning (2-socket Threadripper Pro):"
    echo "  numactl --cpunodebind=0 ./keyhunt-cyclone ... &"
    echo "  numactl --cpunodebind=1 ./keyhunt-cyclone ... &"
    echo ""
    echo "  Benchmark:"
    echo "  make bench && ./benchmark"
    echo "======================================================"
else
    echo "❌ BUILD FAILED — see /tmp/build_tr7000.log"
    tail -20 /tmp/build_tr7000.log
    exit 1
fi
