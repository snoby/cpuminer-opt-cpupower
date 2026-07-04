#!/bin/bash
# mine-neuromorph.sh — NUMA-aware NeuroMorph (Cereblix CRB) launcher
#
# NeuroMorph's per-epoch 64 MiB dataset is built ONCE per process (see
# algo/neuromorph/neuromorph.c's g_nm_dataset) and shared read-only by all
# threads in that process — there is no in-binary per-NUMA-node replication
# (unlike yespower's --cache-fit, which handles topology inside the binary).
# On a multi-NUMA-node box, a single process spanning both nodes means half
# its threads walk that dataset over the cross-node interconnect every hash.
#
# Measured on an EPYC 7642 (2 NUMA nodes, 24 physical cores/node):
#   1 process,  48 threads (dataset on node0 only): 57.0 kH/s, ~1150-1200 H/s/thread, uneven across nodes
#   2 processes, 24 threads each, membind to their own node: 58.97 kH/s, ~1230 H/s/thread, uniform
#
# So: one process per NUMA node, each with --membind to keep its dataset
# build (and scratch allocations) in local DRAM. Single-NUMA-node systems
# (desktops, single-socket non-NUMA servers) just get one plain instance.
#
# Requirements:
#   numactl, /sys filesystem
#
# Usage:
#   ./mine-neuromorph.sh [options]
#
# Options:
#   -a ALGO       Algorithm (default: neuromorph)
#   -o URL        Stratum URL  (e.g. stratum+tcp://us.cereblix.com:3333)
#   -u USER       Pool username / wallet address (crb1...). Each NUMA-node
#                 instance mines as USER.nodeN so pool-side stats separate
#                 them; on a single-node system USER is used as-is.
#   -p PASS       Pool password (default: x)
#   -b BINARY     Path to cpuminer binary (default: ./cpuminer)
#   -t THREADS    Override thread count PER INSTANCE (default: physical
#                 cores on that instance's NUMA node)
#   -n            Dry run — print commands without executing
#   -h            Show this help
#   --api-bind=ADDR:PORT   Enable the JSON stats HTTP API. Each instance gets
#                 its own port (PORT, PORT+1, PORT+2, ...) since only one
#                 process can bind a given port.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
ALGO="neuromorph"
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

# getopts only understands short options — pull --api-bind=ADDR:PORT out of
# the argument list (wherever it appears) before getopts sees the rest.
API_BIND=""
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --api-bind=*) API_BIND="${arg#--api-bind=}" ;;
        *) ARGS+=("$arg") ;;
    esac
done
set -- "${ARGS[@]}"

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

# Get all physical cores system-wide (first sibling of each core pair)
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

# Expand a CPU list string like "0-23,48-71" into space-separated numbers
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

# Physical cores (from a given candidate list) that belong to NUMA node N
node_physical_cores() {
    local node="$1"
    local candidates="$2"
    local node_cpulist_file="/sys/devices/system/node/node${node}/cpulist"
    [[ -f "$node_cpulist_file" ]] || { echo ""; return; }
    local node_cpus
    node_cpus=$(expand_cpulist "$(cat "$node_cpulist_file")")
    local result=""
    for cpu in $candidates; do
        for ncpu in $node_cpus; do
            if [[ "$cpu" -eq "$ncpu" ]]; then
                result="$result $cpu"
                break
            fi
        done
    done
    echo $result | tr ' ' '\n' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

NUM_NODES=$(numactl --hardware | awk '/^available:/{print $2}')
echo "Detected ${NUM_NODES} NUMA node(s)"

ALL_PHYS=$(all_physical_cores)
PIDS=()

if [[ "$NUM_NODES" -le 1 ]]; then
    # -------------------------------------------------------------------
    # Single NUMA node: one process, all physical cores, no cross-node
    # dataset traffic possible regardless — plain launch.
    # -------------------------------------------------------------------
    THREADS="${THREAD_OVERRIDE:-$(echo $ALL_PHYS | wc -w)}"
    CPU_LIST=$(echo $ALL_PHYS | tr ' ' ',')

    CMD="numactl --membind=0 --physcpubind=${CPU_LIST} \
        ${BINARY} \
        -a ${ALGO} \
        -o ${POOL_URL} \
        -u ${POOL_USER} \
        -p ${POOL_PASS} \
        -t ${THREADS}"
    [[ -n "$API_BIND" ]] && CMD="${CMD} --api-bind=${API_BIND}"

    echo "--- [single node] threads=${THREADS} cpus=${CPU_LIST}"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "    DRY RUN: $CMD"
    else
        eval "$CMD" &
        PIDS+=($!)
    fi
else
    # -------------------------------------------------------------------
    # Multi-NUMA (EPYC Rome/Milan/Genoa, multi-socket, Threadripper Pro):
    # one process per node, membind + physcpubind to that node's own
    # physical cores, so its dataset build lands in local DRAM.
    # -------------------------------------------------------------------
    echo "Platform: Multi-NUMA (${NUM_NODES} nodes) — one instance per node"

    API_PORT_BASE=""
    API_HOST=""
    if [[ -n "$API_BIND" ]]; then
        API_HOST="${API_BIND%:*}"
        API_PORT_BASE="${API_BIND##*:}"
    fi

    for (( node=0; node<NUM_NODES; node++ )); do
        NODE_CPUS=$(node_physical_cores "$node" "$ALL_PHYS")
        if [[ -z "$NODE_CPUS" ]]; then
            echo "WARNING: no physical cores found for node ${node}, skipping"
            continue
        fi
        NODE_THREADS="${THREAD_OVERRIDE:-$(echo $NODE_CPUS | wc -w)}"
        NODE_CPU_LIST=$(echo $NODE_CPUS | tr ' ' ',')

        CMD="numactl --membind=${node} --physcpubind=${NODE_CPU_LIST} \
            ${BINARY} \
            -a ${ALGO} \
            -o ${POOL_URL} \
            -u ${POOL_USER}.node${node} \
            -p ${POOL_PASS} \
            -t ${NODE_THREADS}"
        if [[ -n "$API_BIND" ]]; then
            CMD="${CMD} --api-bind=${API_HOST}:$(( API_PORT_BASE + node ))"
        fi

        echo "--- [node${node}] membind=${node} cpus=${NODE_CPU_LIST} threads=${NODE_THREADS}"
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "    DRY RUN: $CMD"
        else
            eval "$CMD" &
            PIDS+=($!)
        fi
    done
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
    echo ""
    echo "All instances started (pids: ${PIDS[*]:-none}). Waiting..."
    wait
    echo "All instances exited."
fi
