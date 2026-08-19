#!/bin/bash
# cpuminer-opt-cpupower build + versioned package.
#   ./build.sh                 plain build (no PGO)
#   ./build.sh --package      build, then assemble a deployable package from packaging/
#   ./build.sh --package [scp_path]   ...also upload + auto-increment
#
# Versioning follows the tequila packaging model:
#   - Version comes from git (tag-count-hash), or a VER file if present.
#   - HiveOS parses the tarball name by splitting on '-': only the LAST
#     dash-field is the version; everything before it is the miner name.
#   - Therefore the version MUST NOT contain a dash.  git describe emits
#     'tag-count-hash' (e.g. 1.4-35-g6954ecb) which has dashes, so we rewrite
#     every '-' to '_' (official example: 1.0_beta).  The miner name MAY
#     contain dashes (e.g. sha3-256t-miner-1.2.3 -> miner 'sha3-256t-miner',
#     version '1.2.3').
#   - Package filename: <MINER>-<VER>[.pkg_ver].tar.gz  (no variant/arch suffix
#     — a suffix after the version would corrupt the HiveOS version parse, and
#     one before it would change the miner name and break CUSTOM_MINER match)
#   - pkg_ver auto-increments against existing files on the SCP server so HiveOS
#     sees a new version and pulls the update.
#   - CUSTOM_MINER in wallet.conf must equal <MINER> EXACTLY (the part before
#     the trailing -version), or the miner dies with the "should be ..." error.
#
# Binary is -march=znver2 (AMD Rome/Zen2): runs on Rome/Milan/Genoa.
set -e

# -march=znver2 targets AMD Rome (Zen2, e.g. EPYC 7742) and runs on any Zen2/+
# (Rome/Milan/Genoa). Portable across the fleet; NOT native-specific.
BASE_CFLAGS="-O3 -march=znver2 -pthread -funroll-loops -ffast-math -fomit-frame-pointer -falign-functions=32 -falign-loops=32 -fvectorize -fslp-vectorize -DYP2_STAGED_PREFETCH"

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
    BASE_CFLAGS="-O3 -march=znver2 -pthread -funroll-loops -ffast-math -fomit-frame-pointer -ftree-vectorize -DYP2_STAGED_PREFETCH"
fi
echo "=== Compiler: $CC ($($CC --version | head -1)) ==="

build() {
    export CFLAGS="$BASE_CFLAGS"
    export LDFLAGS="-pthread"
    ./configure --with-curl
    make clean
    make -j"$(nproc)"
}

# Derive version: use VER file if present, else git describe.
# The version MUST NOT contain a dash (HiveOS treats the last dash-field of the
# tarball name as the version), so rewrite every '-' to '_' (e.g. git describe
# '1.4-35-g6954ecb' -> '1.4_35_g6954ecb').  Also strip a leading 'v' so the
# version is purely numeric-ish.
derive_version() {
    if [ -f VER ]; then
        VER="$(cat VER | xargs)"
    else
        VER="$(git describe --tags 2>/dev/null || echo "v0.0.0")"
    fi
    [ -z "$VER" ] && VER="v0.0.0"
    VER="${VER#v}"
    VER="${VER//-/_}"
    echo "$VER"
}

# HiveOS custom-get extracts the tarball into /hive/miners/custom/ and expects a
# TOP-LEVEL DIRECTORY named after the miner (cpuminer/...), so the payload lands
# at /hive/miners/custom/cpuminer/.  Without the wrapper dir the binary/scrips
# scatter into /hive/miners/custom/ itself and HiveOS can't cd into the miner
# dir -> miner won't start.  Wrap the flat payload dir under <MINER>/, keeping
# the flat dir intact for direct (non-HiveOS) launches.
make_tarball() {
    local payload="$1" archive="$2" miner="$3"
    local stage
    stage="$(mktemp -d)"
    mkdir -p "$stage/$miner"
    cp -r "$payload"/. "$stage/$miner/"
    tar czf "$archive" -C "$stage" "$miner"
    rm -rf "$stage"
}

mkpackage() {
    local pkgdir="packaging/cpuminer"
    local VER="$(derive_version)"
    # HiveOS parses '<miner>-<version>.tar.gz': last dash-field = version.
    local PACKAGE_BASENAME="cpuminer-${VER}"
    local out="cpuminer-civiclight-package"
    local archive="${PACKAGE_BASENAME}.tar.gz"
    echo "=== Assembling package in $out/ ==="
    rm -rf "$out"
    rm -f "$archive"
    mkdir -p "$out"
    cp cpuminer "$out/cpuminer"
    for f in h-run.sh h-stats.sh h-config.sh h-manifest.conf cpuminer.sh; do
        if [[ -f "$pkgdir/$f" ]]; then cp "$pkgdir/$f" "$out/$f"; fi
    done
    chmod +x "$out/cpuminer" "$out/h-run.sh" "$out/h-stats.sh" "$out/h-config.sh" "$out/cpuminer.sh" 2>/dev/null || true
    make_tarball "$out" "$archive" cpuminer
    echo "=== Package created: $archive ==="
    ls -la "$archive"
}

upload_package() {
    local scp_path="$1"
    local VER
    VER="$(derive_version)"
    local MINER=cpuminer
    local pkg_ver=1
    local increment=1

    echo "=== Uploading versioned package ==="
    echo "Version: $VER"
    echo "SCP path: $scp_path"

    # Auto-increment package version against server
    while true; do
        CHECK_FILENAME="${MINER}-${VER}.${pkg_ver}.tar.gz"
        if ssh snoby@public.viporlab.net "test -f /home/snoby/startup/docker_start_up_commands/$scp_path$CHECK_FILENAME"; then
            echo "Existing: $CHECK_FILENAME -> incrementing"
            pkg_ver=$((increment + 1))
            increment=$((increment + 1))
        else
            echo "Version $pkg_ver available"
            break
        fi
    done

    # NOTE: no variant/arch suffix.  Any suffix AFTER the version would make
    # HiveOS's last-dash-field parser read it as part of the version (violates
    # the naming rules), and a suffix BEFORE the version would change the miner
    # name and break CUSTOM_MINER matching.  Version bumps carry updates.
    local FILENAME="${MINER}-${VER}.${pkg_ver}.tar.gz"

    # Package payload dir (same one mkpackage assembles into).  Wrap under
    # cpuminer/ so HiveOS custom-get extracts it to /hive/miners/custom/cpuminer/.
    local PAYLOAD="cpuminer-civiclight-package"
    make_tarball "$PAYLOAD" "$FILENAME" cpuminer
    echo "Created: $FILENAME"
    scp "$FILENAME" "snoby@public.viporlab.net:/home/snoby/startup/docker_start_up_commands/$scp_path"
    echo "Uploaded: $FILENAME"
    echo "=== Upload complete ==="
}

build
echo "=== Build complete ==="

if [[ "${1:-}" == "--package" ]]; then
    mkpackage
    # Default SCP path = the historical cpuminer package server share
    # (public.viporlab.net == downloads.viporlab.net == 10.0.0.212).
    upload_package "${2:-snoby_share/files/}"
fi
