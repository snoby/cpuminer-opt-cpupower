#!/bin/bash
# Two-phase PGO build: instrument -> profile via 60s benchmark -> rebuild.
# ./build.sh          full PGO build (~4 min) when toolchain supports it
# ./build.sh --quick  single-phase build, reuses existing profile if present
#
# Falls back automatically: no clang -> gcc; no llvm-profdata -> plain build.
# Binary is -march=native: always rebuild on the machine that will mine.
set -e

BASE_CFLAGS="-O3 -march=native -pthread -funroll-loops -ffast-math -fomit-frame-pointer -falign-functions=32 -falign-loops=32 -fvectorize -fslp-vectorize"
PGO_DIR="$(pwd)/pgo-profile"
PROFDATA="$PGO_DIR/merged.profdata"

# Pick compiler: prefer clang (measured faster for yespower), else newest gcc
if command -v clang >/dev/null; then
    export CC=clang CXX=clang++
else
    for g in gcc-14 gcc-13 gcc-12 gcc; do
        if command -v "$g" >/dev/null; then
            export CC="$g" CXX="${g/gcc/g++}"
            break
        fi
    done
    # gcc doesn't know clang's vectorize flags
    BASE_CFLAGS="-O3 -march=native -pthread -funroll-loops -ffast-math -fomit-frame-pointer -ftree-vectorize"
fi
echo "=== Compiler: $CC ($($CC --version | head -1)) ==="

LLVM_PROFDATA="$(command -v llvm-profdata-20 || command -v llvm-profdata || true)"

build() {
    local extra="$1"
    # -flto breaks the -fprofile-generate link (gold plugin); only use it
    # on non-instrumented clang builds. Skip LTO for gcc (type-mismatch warnings).
    local lto=""
    [[ "$CC" == clang && "$extra" != *profile-generate* ]] && lto="-flto"
    export CFLAGS="$BASE_CFLAGS $lto $extra"
    export LDFLAGS="-pthread $lto $extra"
    ./configure --with-curl
    make clean
    make -j"$(nproc)"
}

# PGO only wired up for clang + llvm-profdata; otherwise plain build
if [[ "$CC" != clang || -z "$LLVM_PROFDATA" || "${1:-}" == "--quick" ]]; then
    if [[ "$CC" == clang && -f "$PROFDATA" && "${1:-}" == "--quick" ]]; then
        echo "=== Quick build reusing $PROFDATA ==="
        build "-fprofile-use=$PROFDATA"
    else
        [[ "$CC" == clang && -z "$LLVM_PROFDATA" ]] && echo "=== llvm-profdata not found: building without PGO ==="
        build ""
    fi
    echo "=== Build complete (no new profile) ==="
    exit 0
fi

# Phase 1: instrumented build + profile collection
mkdir -p "$PGO_DIR"
rm -f "$PGO_DIR"/*.profraw "$PROFDATA"
build "-fprofile-generate=$PGO_DIR"
echo "=== Collecting profile (60s benchmark) ==="
timeout --signal=INT 60 ./cpuminer -a yespower --benchmark \
    -t "$(nproc --all | awk '{print int($1/2)}')" || true
"$LLVM_PROFDATA" merge -output="$PROFDATA" "$PGO_DIR"/*.profraw

# Phase 2: optimized build using the profile
build "-fprofile-use=$PROFDATA"
echo "=== PGO build complete ==="
