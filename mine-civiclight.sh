#!/bin/bash
# mine-civiclight.sh — mine CivicNet (CIVIC) civiclight v2 to rabbitminer pool.
#
# Targets the local cpuminer-opt-cpupower build with the civiclight algo.
#
# Usage:
#   ./mine-civiclight.sh [options]
#
# Options:
#   -o URL        Stratum URL          (default: stratum+tcp://nl.rabbitminer.cc:1104)
#   -u USER       Worker login        (default: civc1qxd4rn6jlqe4t5l4d3u0sxz6lhvp8py32ssx34v.ethpow)
#   -p PASS       Worker password    (default: x)
#   -t THREADS    Thread count     (default: auto-detect physical cores)
#   -b BINARY     cpuminer binary (default: ./cpuminer)
#   -n            Dry run — print the command without executing
#   -h            Show this help
#
# Notes:
#   - Runs one thread per PHYSICAL core (no SMT); civiclight is memory-hard
#     and SMT siblings contend for the same L2/L3 + huge-page working set.
#   - On multi-NUDA / EPYC boxes, --cache-fit lets the miner pick the best
#     cores; pass -t to force a specific thread count instead.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
ALGO="civiclight"
POOL_URL="stratum+tcp://lab.viporlab.net:5090"
POOL_USER="civc1qxd4rn6jlqe4t5l4d3u0sxz6lhvp8py32ssx34v.ethpow"
POOL_PASS="x"
BINARY="$(cd "$(dirname "$0")" && pwd)/cpuminer"
THREAD_OVERRIDE=""
#DIFF_MULT="1"
DRY_RUN=0

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'
    exit 0
}

while getopts "o:u:p:t:b:nh" opt; do
    case $opt in
        o) POOL_URL="$OPTARG" ;;
        u) POOL_USER="$OPTARG" ;;
        p) POOL_PASS="$OPTARG" ;;
        t) THREAD_OVERRIDE="$OPTARG" ;;
        b) BINARY="$OPTARG" ;;
        n) DRY_RUN=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: cpuminer binary not found or not executable: $BINARY" >&2
    echo "Build it first: ./build.sh  (or pass -b /path/to/cpuminer)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Physical-core count (no SMT)
# ---------------------------------------------------------------------------
count_physical_cores() {
    local phys=0
    for cpu_dir in /sys/devices/system/cpu/cpu[0-9]*/; do
        local cpu
        cpu=$(basename "$cpu_dir" | tr -d 'cpu')
        [[ "$cpu" =~ ^[0-9]+$ ]] || continue
        local sf="${cpu_dir}topology/thread_siblings_list"
        if [[ ! -f "$sf" ]]; then
            phys=$((phys + 1))
            continue
        fi
        local first
        first=$(cut -d, -f1 "$sf" | cut -d- -f1)
        [[ "$cpu" -eq "$first" ]] && phys=$((phys + 1))
    done
    echo "$phys"
}

THREADS="${THREAD_OVERRIDE:-$(count_physical_cores)}"

# ---------------------------------------------------------------------------
# Build & run
# ---------------------------------------------------------------------------
CMD="$BINARY -a ${ALGO} -o ${POOL_URL} -u ${POOL_USER} -p ${POOL_PASS} -t ${THREADS}"

echo "CivicNet (CIVIC) civiclight v2 miner"
echo "  binary : $BINARY"
echo "  pool   : $POOL_URL"
echo "  worker : $POOL_USER"
echo "  threads: $THREADS (physical cores)"
echo ""

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY RUN: $CMD"
    exit 0
fi

exec $CMD
