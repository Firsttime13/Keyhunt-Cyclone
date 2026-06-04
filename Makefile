##############################################################
# Keyhunt-Cyclone — Makefile  (v2 — 2025)
#
# Updates:
#  - AMD EPYC 9004 official tuning: --param prefetch-latency=300
#  - -funroll-all-loops (replaces limited unroll)
#  - AOCC 4.0 support target (amd-aocc)
#  - xxhash inline (no external dep)
#  - GCC 13+ required for znver4
#  - GCC 11+ required for znver3
#  - Profile-guided optimization (PGO) target
#  - Parallel make default (-j$(nproc))
##############################################################

TARGET  := keyhunt-cyclone
CC      := gcc
CFLAGS  := -O3 -pipe -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
CFLAGS  += -Iinclude
LDFLAGS := -lm -lpthread -lgmp

# ── Default architecture ─────────────────────────────────────
ARCH ?= native

# ── Architecture-specific flags ─────────────────────────────
ifeq ($(ARCH),znver3)
    # EPYC 7003 (Milan) / EPYC 7773X
    # GCC 11+ required
    CFLAGS += -march=znver3 -mtune=znver3
    CFLAGS += -mavx512f -mavx512bw -mavx512vl -mavx512dq
    CFLAGS += -mavx512ifma -mavx512vbmi -mavx512vbmi2
    CFLAGS += -mvaes -mvpclmulqdq
    CFLAGS += -funroll-all-loops
    CFLAGS += -fprefetch-loop-arrays
    CFLAGS += --param prefetch-latency=300
    CFLAGS += --param l1-cache-size=32
    CFLAGS += --param l2-cache-size=512
    CFLAGS += --param l3-cache-size=786432
    CFLAGS += -fno-plt -fomit-frame-pointer
    CFLAGS += -DHAVE_AVX512 -DAMD_ZNVER=3
    $(info [BUILD] Target: EPYC 7773X / Milan-X  [znver3 + full AVX-512])

else ifeq ($(ARCH),znver4)
    # EPYC 9004 (Genoa) / Threadripper PRO 7000
    # GCC 13+ required
    CFLAGS += -march=znver4 -mtune=znver4
    CFLAGS += -mavx512f -mavx512bw -mavx512vl -mavx512dq
    CFLAGS += -mavx512ifma -mavx512vbmi -mavx512vbmi2
    CFLAGS += -mvaes -mvpclmulqdq
    CFLAGS += -mavx512vnni -mavx512bf16 -mavx512fp16
    CFLAGS += -funroll-all-loops
    CFLAGS += -fprefetch-loop-arrays
    # AMD official EPYC 9004 tuning guide value:
    CFLAGS += --param prefetch-latency=300
    CFLAGS += --param l1-cache-size=32
    CFLAGS += --param l2-cache-size=1024
    CFLAGS += --param l3-cache-size=1048576
    CFLAGS += -fno-plt -fomit-frame-pointer
    # Enable XXH3 auto-vectorize on Zen4 (proven beneficial per xxHash docs)
    CFLAGS += -DXXH_ENABLE_AUTOVECTORIZE
    CFLAGS += -DHAVE_AVX512 -DAMD_ZNVER=4
    $(info [BUILD] Target: Threadripper 7000 / EPYC Genoa  [znver4 + AVX-512])

else ifeq ($(ARCH),x86-64-v4)
    # Generic AVX-512 capable (portable binary)
    CFLAGS += -march=x86-64-v4 -mtune=generic
    CFLAGS += -mavx512f -mavx512bw -mavx512vl -mavx512dq
    CFLAGS += -funroll-all-loops -fprefetch-loop-arrays
    CFLAGS += --param prefetch-latency=200
    CFLAGS += -DHAVE_AVX512
    $(info [BUILD] Target: Generic AVX-512  [x86-64-v4])

else ifeq ($(ARCH),x86-64-v3)
    # Generic AVX2 (no AVX-512)
    CFLAGS += -march=x86-64-v3 -mtune=generic
    CFLAGS += -funroll-all-loops -fprefetch-loop-arrays
    $(info [BUILD] Target: Generic AVX2  [x86-64-v3])

else
    # native — auto detect
    CFLAGS += -march=native -mtune=native
    HAVE_AVX512_CHECK := $(shell echo | $(CC) -mavx512f -xc - -c -o /dev/null 2>/dev/null && echo 1)
    ifeq ($(HAVE_AVX512_CHECK),1)
        CFLAGS += -mavx512f -mavx512bw -mavx512vl -DHAVE_AVX512
        $(info [BUILD] AVX-512 auto-detected)
    endif
    CFLAGS += -funroll-all-loops -fprefetch-loop-arrays
    CFLAGS += --param prefetch-latency=300
    $(info [BUILD] Target: native  [auto-detect])
endif

# ── LTO ──────────────────────────────────────────────────────
CFLAGS += -flto=auto

# ── OpenMP (optional) ────────────────────────────────────────
ifeq ($(OMP),1)
    CFLAGS  += -fopenmp
    LDFLAGS += -lgomp
    $(info [BUILD] OpenMP enabled)
endif

# ── Source files ─────────────────────────────────────────────
SRCS :=  src/main.c           \
         src/keyhunt.c        \
         src/secp256k1.c      \
         src/sha256.c         \
         src/ripemd160.c      \
         src/util.c           \
         bsgs/bsgs_core.c     \
         cyclone/cyclone_ec.c \
         avx512/avx512_sha256.c \
         filter/binary_fuse.c  \
         kangaroo/kangaroo.c

OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)

# ── Default target ───────────────────────────────────────────
.PHONY: all epyc threadripper generic debug pgo aocc clean install bench

all: $(TARGET)
	@echo ""
	@echo "  ✅  Built: ./$(TARGET)"
	@echo "  Run:  ./$(TARGET) -h"
	@echo ""

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Dependency tracking
-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# ── CPU preset targets ───────────────────────────────────────
epyc:
	@echo "Building for AMD EPYC 7773X (znver3 + AVX-512)..."
	$(MAKE) ARCH=znver3 -j$(shell nproc)

threadripper:
	@echo "Building for AMD Threadripper 7000 (znver4 + AVX-512)..."
	$(MAKE) ARCH=znver4 -j$(shell nproc)

generic:
	$(MAKE) ARCH=x86-64-v3 -j$(shell nproc)

avx512-generic:
	$(MAKE) ARCH=x86-64-v4 -j$(shell nproc)

# ── AOCC 4.0 target (AMD Optimizing C/C++ Compiler) ─────────
# Best performance on Zen3/Zen4. Download from developer.amd.com
aocc:
	@which clang 2>/dev/null | grep -q aocc || \
	  (echo "AOCC not found. Download from developer.amd.com" && exit 1)
	$(MAKE) CC=clang ARCH=znver4 -j$(shell nproc)

# ── Debug ────────────────────────────────────────────────────
debug:
	$(MAKE) CFLAGS="-O0 -g3 -fsanitize=address,undefined -Iinclude -Wall" \
	        LDFLAGS="-lm -lpthread -lgmp -fsanitize=address,undefined"

# ── Profile-Guided Optimization ──────────────────────────────
# Step 1: build with instrumentation
pgo-gen:
	$(MAKE) CFLAGS="$(CFLAGS) -fprofile-generate" \
	        LDFLAGS="$(LDFLAGS) -fprofile-generate" \
	        TARGET=keyhunt-cyclone-pgo-instr

# Step 2: run a training workload
pgo-train: pgo-gen
	@echo "Running PGO training (10 seconds BSGS)..."
	./keyhunt-cyclone-pgo-instr -m bsgs -f /dev/null -b 30 -t 4 -q || true

# Step 3: build optimized binary using profile data
pgo-use:
	$(MAKE) CFLAGS="$(CFLAGS) -fprofile-use -fprofile-correction" \
	        TARGET=keyhunt-cyclone-pgo

pgo: pgo-gen pgo-train pgo-use
	@echo "PGO build complete: ./keyhunt-cyclone-pgo"

# ── Utility tools ────────────────────────────────────────────
bench: tools/benchmark.c $(filter-out src/main.c,$(SRCS))
	$(CC) $(CFLAGS) -o benchmark $^ $(LDFLAGS)
	@echo "Run: ./benchmark"

gen_table: tools/gen_table.c src/secp256k1.c src/sha256.c src/ripemd160.c src/util.c
	$(CC) $(CFLAGS) -o gen_table $^ $(LDFLAGS)

# ── Install ──────────────────────────────────────────────────
PREFIX ?= /usr/local
install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/bin/
	@echo "Installed to $(PREFIX)/bin/$(TARGET)"

# ── GCC version check ────────────────────────────────────────
check-gcc:
	@GCC_VER=$$($(CC) -dumpversion | cut -d. -f1); \
	if [ "$(ARCH)" = "znver4" ] && [ "$$GCC_VER" -lt 13 ]; then \
	  echo "WARNING: GCC $$GCC_VER < 13. znver4 needs GCC 13+."; \
	elif [ "$(ARCH)" = "znver3" ] && [ "$$GCC_VER" -lt 11 ]; then \
	  echo "WARNING: GCC $$GCC_VER < 11. znver3 needs GCC 11+."; \
	else \
	  echo "GCC $$GCC_VER OK for $(ARCH)"; \
	fi

# ── Clean ────────────────────────────────────────────────────
clean:
	rm -f $(OBJS) $(DEPS) $(TARGET) benchmark gen_table
	rm -f keyhunt-cyclone-pgo* *.gcda *.gcno
	@echo "Cleaned."
