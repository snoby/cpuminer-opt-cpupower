#!/bin/bash
# mine-yespower.sh — NUMA-aware yespower launcher
#
# Automatically detects CPU topology and launches cpuminer instances
# optimally bound per CCD.
#
# Supports:
#   - Ryzen 7950X3D / 7900X3D (asymmetric):
#       CCD0 (V-Cache): all physical cores + SMT siblings (all L3-local)
#       CCD1 (standard L3): physical cores limited so total V fits in L3
#   - EPYC Rome (and multi-NUMA AMD generally): one instance per NUMA node
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

# V array size in KB per thread — all current yespower variants:
#   N=2048 r=32  → 128*32*2048 = 8 MB   (yespower, cpupower, urx, litb, inter, sugar)
#   N=4096 r=16  → 128*16*4096 = 8 MB   (yespowerr16)
V_SIZE_KB=8192

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

# Given a space-separated list of physical CPU numbers, return their SMT
# siblings (the non-first logical CPUs sharing each physical core)
get_smt_siblings() {
    local phys_cpus="$1"
    local siblings=""
    for cpu in $phys_cpus; do
        local sf="/sys/devices/system/cpu/cpu${cpu}/topology/thread_siblings_list"
        [[ ! -f "$sf" ]] && continue
        local expanded
        expanded=$(expand_cpulist "$(cat "$sf")")
        for sib in $expanded; do
            [[ "$sib" -ne "$cpu" ]] && siblings="$siblings $sib"
        done
    done
    echo $siblings | tr ' ' '\n' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

# Given a space-separated list of physical CPU numbers, keep only as many
# cores per L3 (CCX) as fit the yespower working set: threads = L3_KB / V_SIZE_KB.
# On EPYC Rome (16MB L3, 3-4 cores per CCX) this selects 2 cores per CCX,
# which benchmarks ~11% faster than using all cores (7771 vs 7016 H/s on 7642).
select_cache_fit_cores() {
    local cpus="$1"
    local selected=""
    local seen_groups=" "
    for cpu in $cpus; do
        local grp_file="/sys/devices/system/cpu/cpu${cpu}/cache/index3/shared_cpu_list"
        if [[ ! -f "$grp_file" ]]; then
            selected="$selected $cpu"
            continue
        fi
        local grp
        grp=$(cat "$grp_file")
        if [[ "$seen_groups" == *" $grp "* ]]; then
            continue
        fi
        seen_groups="${seen_groups}${grp} "
        local l3kb
        l3kb=$(l3_size_kb "$cpu")
        local quota=$(( l3kb / V_SIZE_KB ))
        [[ "$quota" -lt 1 ]] && quota=1
        # phys cores of this group that are in our allowed list
        local count=0
        for member in $(expand_cpulist "$grp"); do
            [[ "$count" -ge "$quota" ]] && break
            for c in $cpus; do
                if [[ "$c" -eq "$member" ]]; then
                    selected="$selected $member"
                    count=$((count + 1))
                    break
                fi
            done
        done
    done
    echo $selected | tr ' ' '\n' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

# Make sure enough 2MB huge pages exist for the planned thread count.
# Each yespower thread needs ~8.2MB -> 5 huge pages after rounding.
# Measured +20% on EPYC 7642 (5840 -> 7016 H/s at 48t).
ensure_hugepages() {
    local total_threads="$1"
    local need=$(( total_threads * 5 + 10 ))
    local have
    have=$(awk '/HugePages_Total/{print $2}' /proc/meminfo)
    if [[ "$have" -ge "$need" ]]; then
        return
    fi
    echo "Huge pages: have ${have}, want ${need} — attempting to set vm.nr_hugepages"
    if [[ "$(id -u)" -eq 0 ]]; then
        sysctl -w vm.nr_hugepages="$need" || true
    elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
        sudo -n sysctl -w vm.nr_hugepages="$need" || true
    else
        echo "WARNING: cannot set huge pages (need root). Run: sudo sysctl -w vm.nr_hugepages=${need}"
    fi
}

# Return the NUMA node number for a given CPU
cpu_to_numa_node() {
    local cpu="$1"
    for node_dir in /sys/devices/system/node/node[0-9]*/; do
        local node
        node=$(basename "$node_dir" | tr -d 'node')
        [[ -e "${node_dir}cpu${cpu}" ]] && echo "$node" && return
    done
    echo "0"
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
    #
    # Single instance using all 16 physical cores (no SMT).
    # Affinity mask 0xFFFF covers CPUs 0-15 (all physical, no SMT).
    #
    # Empirical results for 7950X3D:
    #   16 threads (all physical): ~5.04 kH/s
    #   20+ threads: L3 thrashing, performance drops
    #
    # Using all physical cores without SMT gives best performance.
    # Use -t to override (default: 16).
    # -----------------------------------------------------------------------
    VCACHE_PHYS_N=$(echo $VCACHE_PHYS | wc -w)
    VCACHE_L3_KB=$(l3_size_kb "$(echo $VCACHE_PHYS | awk '{print $1}')")
    ALL_PHYS=$(all_physical_cores)
    TOTAL_PHYS=$(echo $ALL_PHYS | wc -w)

    # Default to 16 threads (all physical cores, no SMT)
    # This gives ~5.04 kH/s on 7950X3D
    OPT_THREADS=16

    THREADS="${THREAD_OVERRIDE:-${OPT_THREADS}}"

    ALL_PHYS_LIST=$(echo $ALL_PHYS | tr ' ' ',')

    echo "Platform: 3D V-Cache detected"
    echo "Physical cores: ${ALL_PHYS_LIST} (16 total)"
    echo "Optimal threads: ${THREADS} (all physical cores, no SMT)"
    echo "Use -t to override"

    # Build CPU affinity bitmask for cpuminer --cpu-affinity
    # Mask is hex: bit N set if CPU N should be used
    build_affinity_mask() {
        local cpus="$1"
        local mask=0
        for cpu in $cpus; do
            mask=$((mask | (1 << cpu)))
        done
        printf "0x%x" $mask
    }
    
    # Use all physical cores (0-15) for maximum performance
    # Affinity mask for CPUs 0-15: 0xFFFF
    ALL_PHYS_MASK=$(build_affinity_mask "$ALL_PHYS")
    
    ALL_CMD="numactl --membind=0 \
        ${BINARY} \
        -a ${ALGO} \
        -o ${POOL_URL} \
        -u ${POOL_USER} \
        -p ${POOL_PASS} \
        -t ${THREADS} \
        --cpu-affinity=${ALL_PHYS_MASK} --cpu-priority=5"
    echo "--- [All physical cores] threads=${THREADS} cpus=${ALL_PHYS_LIST} affinity=${ALL_PHYS_MASK}"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "    DRY RUN: $ALL_CMD"
    else
        eval "$ALL_CMD" &
    fi

else
    # -----------------------------------------------------------------------
    # Multi-NUMA system (EPYC Rome, Milan, Genoa, Threadripper, etc.)
    # One instance per NUMA node, physical cores only
    # -----------------------------------------------------------------------
    echo "Platform: Multi-NUMA (${NUM_NODES} nodes)"

    # cpuminer --cache-fit handles topology itself: selects L3/8MB cores per
    # CCX, pins threads, and sets per-thread NUMA memory policy.  We only
    # estimate the thread count here to size the huge page pool.
    ALL_PHYS=$(all_physical_cores)
    SELECTED=$(select_cache_fit_cores "$ALL_PHYS")
    TOTAL_THREADS=$(echo $SELECTED | wc -w)
    ensure_hugepages "$TOTAL_THREADS"

    THREAD_ARG=""
    [[ -n "$THREAD_OVERRIDE" ]] && THREAD_ARG="-t ${THREAD_OVERRIDE}"

    CMD="${BINARY} \
        -a ${ALGO} \
        -o ${POOL_URL} \
        -u ${POOL_USER} \
        -p ${POOL_PASS} \
        --cache-fit ${THREAD_ARG}"

    echo "--- [cache-fit] expected threads=${TOTAL_THREADS} (miner decides)"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "    DRY RUN: $CMD"
    else
        eval "$CMD" &
    fi
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
    echo ""
    echo "All instances started. Waiting..."
    wait
    echo "All instances exited."
fi
