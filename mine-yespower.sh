#!/bin/bash
# mine-yespower.sh — NUMA-aware yespower launcher
#
# Automatically detects CPU topology and launches one cpuminer instance
# per NUMA node, bound to physical cores only (no SMT threads).
#
# Supports:
#   - EPYC Rome (and multi-NUMA AMD generally): one instance per NUMA node
#   - Ryzen 7950X3D: single instance pinned to the 3D V-Cache CCD
#   - Any other multi-core x86 Linux system
#
# Requirements:
#   numactl, taskset (util-linux), /sys filesystem
#
# Usage:
#   ./mine-yespower.sh [options]
#
# Options:
#   -a ALGO       Algorithm (default: yespower)
#                 Choices: yespower, yespowerr16, cpupower, yespowerurx,
#                          yespowerlitb, yespowerinter, yespowersugar
#   -o URL        Stratum URL  (e.g. stratum+tcp://pool.example.com:3333)
#   -u USER       Pool username / wallet address
#   -p PASS       Pool password (default: x)
#   -b BINARY     Path to cpuminer binary (default: ./cpuminer)
#   -t THREADS    Override thread count per instance (default: auto)
#   -n            Dry run — print commands without executing
#   -h            Show this help

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
ALGO="yespower"
POOL_URL=""
POOL_USER=""
POOL_PASS="x"
BINARY="$(dirname "$0")/cpuminer"
THREAD_OVERRIDE=""
DRY_RUN=0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'
    exit 0
}

while getopts "a:o:u:p:b:t:nh" opt; do
    case $opt in
        a) ALGO="$OPTARG" ;;
        o) POOL_URL="$OPTARG" ;;
        u) POOL_USER="$OPTARG" ;;
        p) POOL_PASS="$OPTARG" ;;
        b) BINARY="$OPTARG" ;;
        t) THREAD_OVERRIDE="$OPTARG" ;;
        n) DRY_RUN=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$POOL_URL" || -z "$POOL_USER" ]]; then
    echo "ERROR: -o (pool URL) and -u (username) are required." >&2
    echo "Run with -h for help." >&2
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: cpuminer binary not found or not executable: $BINARY" >&2
    exit 1
fi

if ! command -v numactl &>/dev/null; then
    echo "ERROR: numactl not found. Install with: sudo apt install numactl" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Topology helpers
# ---------------------------------------------------------------------------

# Expand a CPU list string like "0-3,8,10-11" into space-separated numbers
expand_cpulist() {
    local list="$1"
    python3 -c "
result = []
for part in '${list}'.split(','):
    part = part.strip()
    if '-' in part:
        a, b = part.split('-')
        result.extend(range(int(a), int(b)+1))
    elif part:
        result.append(int(part))
print(' '.join(map(str, result)))
"
}

# Given a space-separated list of CPU numbers, return only the physical cores
# (first logical CPU per physical core, identified via thread_siblings_list)
filter_physical_cores() {
    local cpus="$1"
    local phys=""
    for cpu in $cpus; do
        local siblings_file="/sys/devices/system/cpu/cpu${cpu}/topology/thread_siblings_list"
        if [[ ! -f "$siblings_file" ]]; then
            # No SMT info — treat all as physical
            phys="$phys $cpu"
            continue
        fi
        local first
        first=$(cut -d, -f1 "$siblings_file" | cut -d- -f1)
        if [[ "$cpu" -eq "$first" ]]; then
            phys="$phys $cpu"
        fi
    done
    echo $phys
}

# Return L3 cache size in KB for a given CPU number
l3_size_kb() {
    local cpu="$1"
    # index3 is typically L3; some systems use a different index
    for idx in 3 2; do
        local f="/sys/devices/system/cpu/cpu${cpu}/cache/index${idx}/level"
        if [[ -f "$f" ]] && [[ "$(cat "$f")" == "3" ]]; then
            local size_file="/sys/devices/system/cpu/cpu${cpu}/cache/index${idx}/size"
            local raw
            raw=$(cat "$size_file")
            # raw is like "32768K" or "98304K"
            echo "${raw%K}"
            return
        fi
    done
    echo 0
}

# ---------------------------------------------------------------------------
# Get all physical cores system-wide (first sibling of each core pair)
# ---------------------------------------------------------------------------
all_physical_cores() {
    local phys=""
    for cpu_dir in /sys/devices/system/cpu/cpu[0-9]*/; do
        local cpu
        cpu=$(basename "$cpu_dir" | tr -d 'cpu')
        [[ "$cpu" =~ ^[0-9]+$ ]] || continue
        local siblings_file="${cpu_dir}topology/thread_siblings_list"
        if [[ ! -f "$siblings_file" ]]; then
            phys="$phys $cpu"
            continue
        fi
        local first
        first=$(cut -d, -f1 "$siblings_file" | cut -d- -f1)
        [[ "$cpu" -eq "$first" ]] && phys="$phys $cpu"
    done
    echo $phys | tr ' ' '\n' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

# ---------------------------------------------------------------------------
# Detect physical CPUs on V-Cache CCDs (L3 >= 64MB) — for info/logging only
# ---------------------------------------------------------------------------
detect_vcache_phys_cpus() {
    local vcache_cpus=""
    for cpu_dir in /sys/devices/system/cpu/cpu[0-9]*/; do
        local cpu
        cpu=$(basename "$cpu_dir" | tr -d 'cpu')
        [[ "$cpu" =~ ^[0-9]+$ ]] || continue

        local kb
        kb=$(l3_size_kb "$cpu")
        if [[ "$kb" -ge 65536 ]]; then   # >= 64 MB => V-Cache CCD
            local siblings_file="${cpu_dir}topology/thread_siblings_list"
            if [[ -f "$siblings_file" ]]; then
                local first
                first=$(cut -d, -f1 "$siblings_file" | cut -d- -f1)
                [[ "$cpu" -eq "$first" ]] && vcache_cpus="$vcache_cpus $cpu"
            else
                vcache_cpus="$vcache_cpus $cpu"
            fi
        fi
    done
    echo $vcache_cpus | tr ' ' '\n' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

# ---------------------------------------------------------------------------
# Build the run command for one instance
# ---------------------------------------------------------------------------
run_instance() {
    local label="$1"
    local membind="$2"       # NUMA node number(s) for --membind
    local cpu_list="$3"      # comma-separated physical CPU list
    local threads="$4"

    local cmd="numactl --membind=${membind} --physcpubind=${cpu_list} \
        ${BINARY} \
        -a ${ALGO} \
        -o ${POOL_URL} \
        -u ${POOL_USER} \
        -p ${POOL_PASS} \
        -t ${threads}"

    echo "--- [${label}] membind=${membind} cpus=${cpu_list} threads=${threads}"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "    DRY RUN: $cmd"
    else
        eval "$cmd" &
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

NUM_NODES=$(numactl --hardware | awk '/^available:/{print $2}')
echo "Detected ${NUM_NODES} NUMA node(s)"

VCACHE_PHYS=$(detect_vcache_phys_cpus)

if [[ -n "$VCACHE_PHYS" && "$NUM_NODES" -le 2 ]]; then
    # -----------------------------------------------------------------------
    # Desktop with 3D V-Cache (e.g. 7950X3D, 7900X3D)
    # Use ALL physical cores (no SMT), but log which ones have V-Cache.
    # V-Cache cores run yespower faster due to huge L3, non-V-Cache cores
    # still contribute — better than leaving half the CPU idle.
    # -----------------------------------------------------------------------
    ALL_PHYS=$(all_physical_cores)
    VCACHE_LIST=$(echo $VCACHE_PHYS | tr ' ' ',')
    CPU_LIST=$(echo $ALL_PHYS | tr ' ' ',')
    TOTAL_PHYS=$(echo $ALL_PHYS | wc -w)
    THREADS="${THREAD_OVERRIDE:-${TOTAL_PHYS}}"

    echo "Platform: 3D V-Cache detected"
    echo "V-Cache physical cores (fast): ${VCACHE_LIST}"
    echo "All physical cores (no SMT):   ${CPU_LIST}"
    echo "Threads: ${THREADS}"

    run_instance "All physical cores" "0" "${CPU_LIST}" "${THREADS}"

else
    # -----------------------------------------------------------------------
    # Multi-NUMA system (EPYC Rome, Milan, Genoa, Threadripper, etc.)
    # One instance per NUMA node, physical cores only
    # -----------------------------------------------------------------------
    echo "Platform: Multi-NUMA (${NUM_NODES} nodes)"

    for node in $(seq 0 $((NUM_NODES - 1))); do
        # Get the CPU list for this NUMA node
        NODE_CPULIST_RAW=$(cat "/sys/devices/system/node/node${node}/cpulist" 2>/dev/null || true)
        if [[ -z "$NODE_CPULIST_RAW" ]]; then
            echo "  Node ${node}: no CPUs, skipping"
            continue
        fi

        NODE_CPUS=$(expand_cpulist "$NODE_CPULIST_RAW")
        PHYS_CPUS=$(filter_physical_cores "$NODE_CPUS")
        COUNT=$(echo $PHYS_CPUS | wc -w)

        if [[ "$COUNT" -eq 0 ]]; then
            echo "  Node ${node}: no physical cores found, skipping"
            continue
        fi

        CPU_LIST=$(echo $PHYS_CPUS | tr ' ' ',')
        THREADS="${THREAD_OVERRIDE:-${COUNT}}"

        run_instance "NUMA node ${node}" "${node}" "${CPU_LIST}" "${THREADS}"

        # Stagger startup slightly so all instances don't hammer the pool
        # simultaneously on first connect
        [[ "$DRY_RUN" -eq 0 ]] && sleep 0.5
    done
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
    echo ""
    echo "All instances started. Waiting..."
    wait
    echo "All instances exited."
fi
