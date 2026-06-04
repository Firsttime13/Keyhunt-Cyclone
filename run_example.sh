#!/usr/bin/env bash
##############################################################
# Keyhunt-Cyclone — scripts/run_example.sh  (v2 — 2025)
# Common usage examples for EPYC 7773X / Threadripper 7000
##############################################################

set -euo pipefail

BIN="./keyhunt-cyclone"
if [ ! -f "$BIN" ]; then
    echo "ERROR: $BIN not found. Run 'make epyc' or 'make threadripper' first."
    exit 1
fi

THREADS=$(nproc)
echo "Detected $THREADS logical CPUs"
echo ""

show_help() {
    echo "Usage: $0 [example_name]"
    echo ""
    echo "Available examples:"
    echo "  bsgs_basic       - BSGS with bit-range 65, all cores"
    echo "  bsgs_save        - BSGS with table save (-S) for fast restart"
    echo "  bsgs_kfactor     - BSGS with k=4 (4x RAM, 4x speed)"
    echo "  bsgs_dance       - BSGS dance submode"
    echo "  bsgs_middleout   - BSGS middleout from range center"
    echo "  bsgs_rangefile   - BSGS from deep.txt range file"
    echo "  bsgs_restart     - BSGS fast restart (tables on disk)"
    echo "  rmd_mode         - RMD160 mode (2x faster than address)"
    echo "  kangaroo         - Pollard's Lambda on narrow range"
    echo "  vanity           - Vanity address search"
    echo "  wif_mask         - WIF partial key search"
    echo "  benchmark        - Run hardware benchmark"
    echo ""
}

# ── Example: basic BSGS ──────────────────────────────────────
run_bsgs_basic() {
    echo "=== BSGS Basic (bit-range 65, $THREADS threads) ==="
    $BIN -m bsgs \
         -f addresses.txt \
         -b 65 \
         -t "$THREADS" \
         --cyclone \
         -s 5 \
         -o found_keys.txt
}

# ── Example: BSGS with table persistence ────────────────────
run_bsgs_save() {
    echo "=== BSGS with table save (-S) ==="
    echo "First run builds bloom/bP tables, saves to disk."
    echo "Subsequent runs load from disk instantly (-6 skips verify)."
    $BIN -m bsgs \
         -f addresses.txt \
         -b 24 \
         -t "$THREADS" \
         --cyclone \
         -S \
         -s 5 \
         -o found_keys.txt
}

# ── Example: BSGS fast restart ───────────────────────────────
run_bsgs_restart() {
    echo "=== BSGS fast restart (tables already on disk) ==="
    $BIN -m bsgs \
         -f addresses.txt \
         -b 24 \
         -t "$THREADS" \
         --cyclone \
         -S -6 \
         -s 5 \
         -o found_keys.txt
}

# ── Example: BSGS k-factor 4 ────────────────────────────────
run_bsgs_kfactor() {
    echo "=== BSGS k=4 (4x baby steps = ~4x giant-step throughput) ==="
    echo "Uses ~4x more RAM. Best for systems with 256+ GB RAM."
    $BIN -m bsgs \
         -f addresses.txt \
         -b 24 \
         -k 4 \
         -t "$THREADS" \
         --cyclone \
         -S \
         -s 5 \
         -o found_keys.txt
}

# ── Example: BSGS dance submode ─────────────────────────────
run_bsgs_dance() {
    echo "=== BSGS dance submode (forward then backward) ==="
    $BIN -m bsgs \
         -f addresses.txt \
         -b 65 \
         -t "$THREADS" \
         --cyclone \
         --submode dance \
         -s 5 \
         -o found_keys.txt
}

# ── Example: BSGS middleout ──────────────────────────────────
run_bsgs_middleout() {
    echo "=== BSGS middleout (expands from range center) ==="
    $BIN -m bsgs \
         -f addresses.txt \
         -b 65 \
         -t "$THREADS" \
         --cyclone \
         --submode middleout \
         -s 5 \
         -o found_keys.txt
}

# ── Example: BSGS from range file ───────────────────────────
run_bsgs_rangefile() {
    echo "=== BSGS from deep.txt range file ==="
    # Create example deep.txt if missing
    if [ ! -f deep.txt ]; then
        echo "Creating example deep.txt..."
        cat > deep.txt << 'EOF'
8000000000000000:9000000000000000
9000000000000000:A000000000000000
A000000000000000:B000000000000000
B000000000000000:C000000000000000
C000000000000000:D000000000000000
D000000000000000:E000000000000000
E000000000000000:F000000000000000
F000000000000000:FFFFFFFFFFFFFFFF
EOF
        echo "deep.txt created with 8 ranges."
    fi
    $BIN -m bsgs \
         -f addresses.txt \
         -b 24 \
         -t "$THREADS" \
         --cyclone \
         -D deep.txt \
         -S \
         -s 10 \
         -o found_keys.txt
    echo "Completed ranges written to: checked-deep.txt"
}

# ── Example: RMD160 mode ─────────────────────────────────────
run_rmd_mode() {
    echo "=== RMD160 mode (~2x faster than address mode) ==="
    echo "Target file should contain 40-char hex hash160 values."
    $BIN -m rmd \
         -f hashes.txt \
         -r 8000000000000000:FFFFFFFFFFFFFFFF \
         -t "$THREADS" \
         --cyclone \
         -s 5 \
         -o found_keys.txt
}

# ── Example: Kangaroo ────────────────────────────────────────
run_kangaroo() {
    echo "=== Kangaroo mode (narrow range) ==="
    $BIN -m kangaroo \
         -f addresses.txt \
         -r 1000000000:2000000000 \
         --cyclone \
         --kangaroo-dp 20 \
         -t "$THREADS" \
         -s 5 \
         -o found_keys.txt
}

# ── Example: Vanity ──────────────────────────────────────────
run_vanity() {
    echo "=== Vanity address search (prefix: 1Key) ==="
    $BIN -m vanity \
         --prefix 1Key \
         -t "$THREADS" \
         -s 5 \
         -o found_keys.txt
}

# ── Example: WIF mask ────────────────────────────────────────
run_wif_mask() {
    echo "=== WIF mask search ==="
    echo "Replace underscores with the unknown characters of your WIF key."
    $BIN -m wif \
         -f addresses.txt \
         -w "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFYigEAa____" \
         -t "$THREADS" \
         -s 5 \
         -o found_keys.txt
}

# ── Example: Benchmark ───────────────────────────────────────
run_benchmark() {
    echo "=== Hardware Benchmark ==="
    if [ ! -f ./benchmark ]; then
        make bench
    fi
    ./benchmark
}

# ── Dispatch ─────────────────────────────────────────────────
case "${1:-help}" in
    bsgs_basic)     run_bsgs_basic     ;;
    bsgs_save)      run_bsgs_save      ;;
    bsgs_restart)   run_bsgs_restart   ;;
    bsgs_kfactor)   run_bsgs_kfactor   ;;
    bsgs_dance)     run_bsgs_dance     ;;
    bsgs_middleout) run_bsgs_middleout ;;
    bsgs_rangefile) run_bsgs_rangefile ;;
    rmd_mode)       run_rmd_mode       ;;
    kangaroo)       run_kangaroo       ;;
    vanity)         run_vanity         ;;
    wif_mask)       run_wif_mask       ;;
    benchmark)      run_benchmark      ;;
    help|*)         show_help          ;;
esac
