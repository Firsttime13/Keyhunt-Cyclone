#!/usr/bin/env bash
##############################################################
# Keyhunt-Cyclone — scripts/build_epyc.sh  (v2 — 2025)
# Optimized build for AMD EPYC 7773X (Milan-X, znver3)
# 64 cores / 128 threads / 768 MB L3 (3D V-Cache)
#
# Flags sourced from:
#  - AMD EPYC 9004 Compiler Options Quick Reference Guide
#  - AMD Best Practice Guide EPYC
#  - AWS AMD EPYC tuning guide (Sep 2025)
##############################################################

set -euo pipefail

echo "======================================================"
echo "  Keyhunt-Cyclone v2 — EPYC 7773X Build"
echo "  Target: znver3 + AVX-512F/BW/VL/DQ/IFMA/VBMI2/VAES"
echo "======================================================"

# ── Verify GCC version (znver3 needs GCC 11+) ─────────────
GCC_VER=$(gcc -dumpversion | cut -d. -f1)
echo "GCC version: $GCC_VER"
if [ "$GCC_VER" -lt 11 ]; then
    echo "ERROR: GCC $GCC_VER < 11 does not support -march=znver3"
    echo "Install: sudo apt install gcc-11  OR  sudo apt install gcc-12"
    exit 1
fi
echo "✓ GCC $GCC_VER OK for znver3"

# ── Check for libgmp ──────────────────────────────────────
if ! ldconfig -p 2>/dev/null | grep -q libgmp; then
    echo "Installing libgmp-dev..."
    sudo apt-get install -y libgmp-dev 2>/dev/null || \
    sudo dnf install -y gmp-devel 2>/dev/null || \
    (echo "Please install libgmp-dev manually" && exit 1)
fi
echo "✓ libgmp found"

# ── Check for xxhash (optional, we use inline) ───────────
echo "✓ Using inline XXH3 (no external xxhash needed)"

# ── Build ─────────────────────────────────────────────────
echo ""
echo "Building with znver3 + all AVX-512 extensions..."
echo "  --param prefetch-latency=300 (AMD EPYC 9004 tuning guide)"
echo "  -funroll-all-loops (replaces limited unroll)"
echo "  3D V-Cache: L3=768MB tuned"
echo ""

make clean
make ARCH=znver3 -j$(nproc) 2>&1 | tee /tmp/build_epyc.log

echo ""
if [ -f keyhunt-cyclone ]; then
    SIZE=$(du -h keyhunt-cyclone | cut -f1)
    echo "======================================================"
    echo "  ✅  BUILD SUCCESS: ./keyhunt-cyclone  ($SIZE)"
    echo "======================================================"
    echo ""
    echo "  Verify AVX-512 is active:"
    echo "  ./keyhunt-cyclone -v -m bsgs -f /dev/null -b 1 2>&1 | head -8"
    echo ""
    echo "  Recommended BSGS run (128 threads, bit-range 65, save tables):"
    echo "  ./keyhunt-cyclone -m bsgs -f addresses.txt -b 65 \\"
    echo "    -t 128 -k 4 --cyclone -S -s 5 --submode sequential"
    echo ""
    echo "  Benchmark first:"
    echo "  make bench && ./benchmark"
    echo "======================================================"
else
    echo "❌ BUILD FAILED — see /tmp/build_epyc.log"
    tail -20 /tmp/build_epyc.log
    exit 1
fi
