#!/bin/bash
# cpuminer-opt-cpupower build.
#   ./build.sh           plain build (no PGO)
#   ./build.sh --package  build, then assemble a deployable package from packaging/
#
# Binary is -march=znver2 (AMD Rome/Zen2): runs on Rome/Milan/Genoa.
set -e

# -march=znver2 targets AMD Rome (Zen2, e.g. EPYC 7742) and runs on any Zen2/+
# (Rome/Milan/Genoa). Portable across the fleet; NOT native-specific.
BASE_CFLAGS="-O3 -march=znver2 -pthread -funroll-loops -ffast-math -fomit-frame-pointer -falign-functions=32 -falign-loops=32 -fvectorize -fslp-vectorize"

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
    BASE_CFLAGS="-O3 -march=znver2 -pthread -funroll-loops -ffast-math -fomit-frame-pointer -ftree-vectorize"
fi
echo "=== Compiler: $CC ($($CC --version | head -1)) ==="

build() {
    export CFLAGS="$BASE_CFLAGS"
    export LDFLAGS="-pthread"
    ./configure --with-curl
    make clean
    make -j"$(nproc)"
}

mkpackage() {
    local pkgdir="packaging/cpuminer"
    local out="cpuminer-civiclight-package"
    echo "=== Assembling package in $out/ ==="
    rm -rf "$out"
    mkdir -p "$out"
    cp cpuminer "$out/cpuminer"
    if [[ -f "$pkgdir/h-run.sh" ]]; then cp "$pkgdir/h-run.sh" "$out/h-run.sh"; fi
    if [[ -f "$pkgdir/h-stats.sh" ]]; then cp "$pkgdir/h-stats.sh" "$out/h-stats.sh"; fi
    tar czf "$out.tar.gz" -C "$out" .
    echo "=== Package created: $out.tar.gz ==="
    ls -la "$out.tar.gz"
}

build
echo "=== Build complete ==="

if [[ "${1:-}" == "--package" ]]; then
    mkpackage
fi
