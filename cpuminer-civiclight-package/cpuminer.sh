#!/bin/bash
# cpuminer.sh — CivicLight NUMA-aware launcher for cpuminer-opt-cpupower.
#
# Adapted from the tequila cpuminer-opt packaging (packaging/cpuminer/cpuminer.sh),
# which is the canonical multi-NUMA launch pattern.  Differences for civiclight:
#   - Algorithm is civiclight (not cuckoo/BFJ).
#   - Per-thread working set is 4.19 MB (2-way: 2 x 2.097 MB scratchpad regions),
#     so hugepage sizing uses 2 x 2MB pages per thread (not the BFJ pool math).
#   - Launch uses the miner's own --cache-fit (in-code per-CCX/NUMA pinning +
#     per-thread memory policy) instead of tequila's --cpu-list/--mem-node.
#
# Retained from tequila:
#   - Topology detection (NUMA nodes, physical cores, SMT factor).
#   - Per-NUMA-node hugepage allocation with compaction + retry.
#   - HiveOS integration (wallet.conf / rig.conf / config.conf / miner_env.conf).
#   - PID/log management, hard_kill_miners, staggered launch, signal traps.
#
# Requirements: numactl, /sys filesystem.  Runs as the miner user (HiveOS custom).
#
# Tunables (env overrides, or /hive/miners/custom/cpuminer/config.conf):
#   ALGO                 (default: civiclight)
#   POOL_ADDRESS         (default: lab.viporlab.net:5090)
#   MINING_ADDRESS/WALLET
#   RIG_NAME/RIG_ID/WORKER_NAME
#   NUM_THREADS_PER_INSTANCE (default: auto -> cache-fit decides)
#   CACHE_FIT_MB         (default: 4  -> civiclight 2-way working set)
#   LAUNCH_STAGGER_SEC   (default: 1)
#   MINER_EXTRA_ARGS     (extra miner args)
#   TEQUILA_HUGEPAGES_PER_NODE (override hugepage reservation per node)

set -eo pipefail

error_exit() {
    echo "ERROR: Script failed at line $1"
    echo "Last command: $BASH_COMMAND"
    exit 1
}
trap 'error_exit $LINENO' ERR

echo "=== CPUMiner (civiclight) Startup ==="
echo "Starting cpuminer.sh at $(date)"

# ====== Headroom ======
ulimit -n 1048576 || true
ulimit -u 262144 || true
ulimit -v unlimited || true

# ====== Tunables ======
: "${ALGO:=civiclight}"
: "${POOL_ADDRESS:=lab.viporlab.net:5090}"
: "${LAUNCH_STAGGER_SEC:=1}"
: "${NUM_THREADS_PER_INSTANCE:=auto}"
: "${CACHE_FIT_MB:=4}"
: "${MINER_TAG:=CIVIC_MINER}"

# Source HiveOS miner env if present
if [ -f "/hive/miners/custom/cpuminer/miner_env.conf" ]; then
    source "/hive/miners/custom/cpuminer/miner_env.conf"
fi

# ====== Sysfs helpers ======
numa_node_count_sysfs() {
    local count=0
    for d in /sys/devices/system/node/node[0-9]*; do
        [ -d "$d" ] && ((count++))
    done
    echo "$count"
}

numa_node_size_mb_sysfs() {
    local nid="$1"
    local f="/sys/devices/system/node/node${nid}/meminfo"
    [ -f "$f" ] && awk '/MemTotal:/ {print int($4/1024); exit}' "$f" 2>/dev/null
}

numa_node_cpus_sysfs() {
    local nid="$1"
    local f="/sys/devices/system/node/node${nid}/cpulist"
    [ -f "$f" ] && cat "$f" 2>/dev/null | tr ',' ' '
}

# Expand a node's CPU list into individual CPU numbers (handles ranges like 0-31).
expand_cpulist() {
    local list="$1" c range lo hi
    for c in $list; do
        if [[ "$c" == *-* ]]; then
            lo="${c%%-*}"; hi="${c##*-}"
            for ((x=lo; x<=hi; x++)); do echo "$x"; done
        else
            echo "$c"
        fi
    done
}

# Return ONLY the physical (primary-sibling) cores of a NUMA node, excluding SMT
# twins.  A CPU is physical iff its thread_siblings_list first member == itself.
# Always returns 0 (the [[ ]] test's status must not propagate under set -e).
numa_node_phys_cpus() {
    local nid="$1" c first
    for c in $(expand_cpulist "$(numa_node_cpus_sysfs "$nid")"); do
        first=$(cut -d, -f1 "/sys/devices/system/cpu/cpu${c}/topology/thread_siblings_list" 2>/dev/null)
        [[ "$first" == "$c" ]] && echo -n "$c "
    done
    return 0
}

# Detect L3 cache groups (CCDs).  Each unique /sys/.../cache/index3/shared_cpu_list
# is one L3 group.  Emits lines: "<size_kb>|<phys_cpu_list>|<cpu_list>"
#   size_kb   = L3 size for this group (KB)
#   phys_list = comma-separated PHYSICAL cores in the group (no SMT)
#   cpu_list  = full comma-separated cpu list (incl SMT) for taskset
# Returns 0 if any CCD found, non-zero if none.
detect_ccds() {
    local found=0
    local seen=""
    for c in $(expand_cpulist "$(cat /sys/devices/system/cpu/online 2>/dev/null | tr ',' ' ')"); do
        local scl="/sys/devices/system/cpu/cpu${c}/cache/index3/shared_cpu_list"
        [ -f "$scl" ] || continue
        local list; list=$(cat "$scl" 2>/dev/null)
        [ -z "$list" ] && continue
        if [[ ",$seen," != *",$list,"* ]]; then
            seen="$seen,$list"
            local sz; sz=$(cat "/sys/devices/system/cpu/cpu${c}/cache/index3/size" 2>/dev/null | tr -d 'K')
            [ -z "$sz" ] && sz=0
            # physical cores in this group
            local phys="" cc
            for cc in $(expand_cpulist "$(echo "$list" | tr ',' ' ')"); do
                local first; first=$(cut -d, -f1 "/sys/devices/system/cpu/cpu${cc}/topology/thread_siblings_list" 2>/dev/null)
                [[ "$first" == "$cc" ]] && phys="$phys $cc"
            done
            phys=$(echo "$phys" | tr ' ' ',' | sed 's/^,//;s/,$//')
            local fulllist; fulllist=$(echo "$list" | tr ',' ' ')
            fulllist=$(echo "$fulllist" | tr ' ' ',')
            echo "${sz}|${phys}|${fulllist}"
            found=1
        fi
    done
    return $(( found ? 0 : 1 ))
}

# ====== Hugepage sizing ======
# civiclight 2-way: each thread maps 2 x 2.097 MB regions -> 2 x 2MB hugepages.
# Estimate the thread count from physical cores (cache-fit will refine it), then
# reserve enough 2MB hugepages per node.
NUMA_NODE_COUNT=$(numa_node_count_sysfs)
(( NUMA_NODE_COUNT == 0 )) && NUMA_NODE_COUNT=1

# Physical cores (first logical CPU per core)
PHYS_CORES=()
declare -A PHYS_SEEN=()
SMT_FACTOR=1
for d in /sys/devices/system/cpu/cpu[0-9]*; do
    [ -d "$d" ] || continue
    n="${d##*/cpu}"
    sib="$(cat "$d/topology/thread_siblings_list" 2>/dev/null || echo "$n")"
    first="$(awk -F, '{split($1,a,"-");print a[1]}' <<<"$sib")"
    set -- $(echo "$sib" | tr ',' ' '); cnt=$#
    (( cnt > SMT_FACTOR )) && SMT_FACTOR=$cnt
    if [[ -z "${PHYS_SEEN[$first]:-}" ]]; then
        PHYS_SEEN[$first]=1
        PHYS_CORES+=("$first")
    fi
done
TOTAL_PHYS="${#PHYS_CORES[@]}"
echo "Topology: ${TOTAL_PHYS} physical cores, SMT factor ${SMT_FACTOR}, ${NUMA_NODE_COUNT} NUMA node(s)"

# Hugepages per thread (2-way civiclight = 2 x 2.097 MB regions, but each region
# rounds UP to 2MB on MAP_HUGETLB, plus the fixed kernel's S/XY/B overhead).
# Measured: 68 threads consumed 340+ hugepages (~5/thread).  Under-sizing this
# (2 or 3) exhausted the pool -> threads fell back to THP and hashrate dropped
# (~46 vs ~50 kH/s).  Use 5 so every thread gets hugepages.
HP_PER_THREAD=5
PAGES_PER_NODE="${TEQUILA_HUGEPAGES_PER_NODE:-}"
if [[ -z "$PAGES_PER_NODE" ]]; then
    # Distribute physical cores across nodes; reserve HP_PER_THREAD per core + margin.
    max_node_cores=0
    for node in $(seq 0 $((NUMA_NODE_COUNT-1))); do
        nc=$(numa_node_cpus_sysfs "$node" | wc -w)
        phys_nc=0
        for c in $(numa_node_cpus_sysfs "$node"); do
            for p in "${PHYS_CORES[@]}"; do
                [ "$c" = "$p" ] && phys_nc=$((phys_nc+1))
            done
        done
        (( phys_nc > max_node_cores )) && max_node_cores=$phys_nc
    done
    (( max_node_cores < 1 )) && max_node_cores=$((TOTAL_PHYS / NUMA_NODE_COUNT))
    # The miner's --cache-fit often runs MORE threads than physical cores (uses
    # SMT), so add a generous margin so no thread falls back to THP (which drops
    # hashrate ~46 vs ~50 kH/s).  Measured: 68 threads x ~5 pages = 340.
    PAGES_PER_NODE=$(( max_node_cores * HP_PER_THREAD + 48 ))
fi
TARGET_HUGEPAGES=$((NUMA_NODE_COUNT * PAGES_PER_NODE))

if (( NUMA_NODE_COUNT >= 2 )); then
    echo "Multi-NUMA ($NUMA_NODE_COUNT nodes): reserving $PAGES_PER_NODE hugepages/node ($TARGET_HUGEPAGES total)"
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    echo 1 > /proc/sys/vm/compact_memory 2>/dev/null || true
    sleep 1
    for ((node=0; node<NUMA_NODE_COUNT; node++)); do
        hp_path="/sys/devices/system/node/node${node}/hugepages/hugepages-2048kB/nr_hugepages"
        [ -f "$hp_path" ] && echo 0 > "$hp_path" 2>/dev/null || true
    done
    sleep 1
    echo 1 > /proc/sys/vm/compact_memory 2>/dev/null || true
    sleep 1
    for ((node=0; node<NUMA_NODE_COUNT; node++)); do
        hp_path="/sys/devices/system/node/node${node}/hugepages/hugepages-2048kB/nr_hugepages"
        [ -f "$hp_path" ] || continue
        echo "$PAGES_PER_NODE" > "$hp_path" 2>/dev/null || true
        actual=$(cat "$hp_path" 2>/dev/null || echo "0")
        if (( actual >= PAGES_PER_NODE )); then
            echo "  Node $node: $actual hugepages OK"
        else
            echo "  Node $node: $actual/$PAGES_PER_NODE hugepages (shortfall: $((PAGES_PER_NODE-actual)))"
            echo 1 > /proc/sys/vm/compact_memory 2>/dev/null || true
            sleep 2
            echo "$PAGES_PER_NODE" > "$hp_path" 2>/dev/null || true
            actual=$(cat "$hp_path" 2>/dev/null || echo "0")
            (( actual >= PAGES_PER_NODE )) && echo "  Node $node: $actual hugepages OK (after retry)" \
                                          || echo "  Node $node: $actual/$PAGES_PER_NODE hugepages STILL SHORT"
        fi
    done
else
    echo "Single NUMA node: setting vm.nr_hugepages to $TARGET_HUGEPAGES"
    sysctl -w vm.nr_hugepages="$TARGET_HUGEPAGES" 2>/dev/null || true
fi

sleep 1

# ====== PID / log dirs ======
PID_DIR="/var/run/cpuminer"
mkdir -p "$PID_DIR" 2>/dev/null || sudo mkdir -p "$PID_DIR" 2>/dev/null || true
# Ensure the dir is writable by the launching user (not just root).
chown "$(id -u)":"$(id -g)" "$PID_DIR" 2>/dev/null || sudo chown "$(id -u)":"$(id -g)" "$PID_DIR" 2>/dev/null || true
LOG_DIR="/var/log/miner/custom"
mkdir -p "$LOG_DIR" 2>/dev/null || sudo mkdir -p "$LOG_DIR" 2>/dev/null || true
chown "$(id -u)":"$(id -g)" "$LOG_DIR" 2>/dev/null || sudo chown "$(id -u)":"$(id -g)" "$LOG_DIR" 2>/dev/null || true

# Stop any previous miner EARLY (before hugepage sizing) so its hugepages are
# freed and the fresh pool can be allocated.  hard_kill_miners is defined below;
# define a minimal early killer here that only needs PID_DIR.
early_kill_miners() {
    shopt -s nullglob
    for pidfile in "$PID_DIR"/*.pid; do
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        [ -n "${pid:-}" ] || { rm -f "$pidfile"; continue; }
        if [ -d "/proc/$pid" ]; then
            if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "cpuminer"; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
        rm -f "$pidfile"
    done
    shopt -u nullglob
}
early_kill_miners

# ====== HiveOS integration ======
# Flight-sheet templated values (HiveOS custom miner) are exposed as:
#   CUSTOM_TEMPLATE = "<address>.<worker>"   (used as the miner -u login)
#   CUSTOM_URL      = "<pool>:<port>"        (used as the miner -o pool)
#   CUSTOM_USER_CONFIG = extra miner args (e.g. POOL_ADDRESS=... overrides)
# These are the PRIMARY source under HiveOS.  Outside HiveOS we fall back to the
# standalone env vars MINING_ADDRESS/WALLET and POOL_ADDRESS.
WALLET_CONFIG=""
[ -f "/hive/conf/wallet.conf" ] && WALLET_CONFIG="/hive/conf/wallet.conf"
[ -f "/hive-config/wallet.conf" ] && WALLET_CONFIG="/hive-config/wallet.conf"

# --- Pool address: CUSTOM_URL wins, else POOL_ADDRESS env ---
hive_pool="${CUSTOM_URL:-}"
[ -n "$hive_pool" ] && POOL_ADDRESS="$hive_pool"

# --- Mining address + worker: CUSTOM_TEMPLATE ("addr.worker") wins ---
mining_address="${MINING_ADDRESS:-}"
rig_name="${RIG_NAME:-}"
if [ -n "$WALLET_CONFIG" ] && [ -f "$WALLET_CONFIG" ]; then
    source "$WALLET_CONFIG"
    # CUSTOM_TEMPLATE holds "<wallet>.<worker>"; split on the LAST dot.
    if [ -n "$CUSTOM_TEMPLATE" ]; then
        mining_address="${CUSTOM_TEMPLATE%.*}"
        worker_part="${CUSTOM_TEMPLATE##*.}"
        # Only treat the suffix as a worker if it differs from the whole (i.e. a dot existed)
        if [ "$CUSTOM_TEMPLATE" != "$worker_part" ] && [ -n "$worker_part" ]; then
            rig_name="$worker_part"
        fi
    fi
    [ -z "$mining_address" ] && mining_address="${WALLET:-}"
fi

HIVE_CONF=""
[ -f "/hive-config/rig.conf" ] && HIVE_CONF="/hive-config/rig.conf"
[ -f "/hive/conf/rig.conf" ] && HIVE_CONF="/hive/conf/rig.conf"
if [ -n "$HIVE_CONF" ] && [ -f "$HIVE_CONF" ]; then
    source "$HIVE_CONF"
    [ -z "$rig_name" ] && rig_name="${RIG_ID:-${WORKER_NAME:-}}"
fi
[ -z "$rig_name" ] && rig_name="$(hostname)"

# --- CUSTOM_USER_CONFIG overrides (flight-sheet "Custom config" field) ---
# Tokens of the form KEY=VALUE are applied as env overrides (e.g. POOL_ADDRESS=,
# MINING_ADDRESS=, RIG_NAME=, THREADS=, CACHE_FIT_MB=, MINER_EXTRA_ARGS=);
# anything else is appended to the miner command line.
if [ -n "$CUSTOM_USER_CONFIG" ]; then
    for tok in $CUSTOM_USER_CONFIG; do
        case "$tok" in
            POOL_ADDRESS=*)      POOL_ADDRESS="${tok#*=}" ;;
            MINING_ADDRESS=*)    mining_address="${tok#*=}" ;;
            RIG_NAME=*)         rig_name="${tok#*=}" ;;
            THREADS=*)         NUM_THREADS_PER_INSTANCE="${tok#*=}" ;;
            CACHE_FIT_MB=*)   CACHE_FIT_MB="${tok#*=}" ;;
            LOCK_MODE=*)       LOCK_MODE="${tok#*=}" ;;
            MINER_EXTRA_ARGS=*) MINER_EXTRA_ARGS="${tok#*=}" ;;
            *)                 EXTRA_MINER_ARGS+=("$tok") ;;
        esac
    done
fi

# config.conf overrides
if [ -f "/hive/miners/custom/cpuminer/config.conf" ]; then
    custom_addr=$(grep -oP 'MINING_ADDRESS=\K[^[:space:]]+' /hive/miners/custom/cpuminer/config.conf 2>/dev/null || true)
    [ -n "$custom_addr" ] && mining_address="$custom_addr"
    custom_rig=$(grep -oP 'RIG_NAME=\K[^[:space:]]+' /hive/miners/custom/cpuminer/config.conf 2>/dev/null || true)
    [ -n "$custom_rig" ] && rig_name="$custom_rig"
    custom_threads=$(grep -oP 'THREADS=\K[0-9]+' /hive/miners/custom/cpuminer/config.conf 2>/dev/null || true)
    [ -n "$custom_threads" ] && NUM_THREADS_PER_INSTANCE="$custom_threads"
fi

if [ -z "$mining_address" ]; then
    echo "ERROR: MINING_ADDRESS/WALLET not set." >&2
    exit 1
fi
if [ -z "$POOL_ADDRESS" ]; then
    echo "ERROR: POOL_ADDRESS not set." >&2
    exit 1
fi

# ====== Binary discovery ======
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
POSSIBLE_PATHS=(
    "${CPUMINER_PATH:-}"
    "$SCRIPT_DIR/cpuminer"
    "/hive/miners/custom/cpuminer/cpuminer"
)
CPUMINER_PATH=""
for path in "${POSSIBLE_PATHS[@]}"; do
    if [ -n "$path" ] && [ -x "$path" ]; then
        CPUMINER_PATH="$path"
        break
    fi
done
if [ -z "$CPUMINER_PATH" ]; then
    echo "ERROR: cpuminer binary not found." >&2
    exit 1
fi
echo "Using cpuminer binary: $CPUMINER_PATH"

# ====== Cleanup ======
cleanup_and_exit() {
    echo "Caught signal, stopping miners..."
    shopt -s nullglob
    for pidfile in "$PID_DIR"/cpu*.pid; do
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        [ -n "$pid" ] && { kill -TERM "$pid" 2>/dev/null || true; }
    done
    sleep 1
    for pidfile in "$PID_DIR"/cpu*.pid; do
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        [ -n "$pid" ] && { kill -9 "$pid" 2>/dev/null || true; }
        rm -f "$pidfile"
    done
    shopt -u nullglob
    exit 0
}
trap cleanup_and_exit INT TERM

hard_kill_miners() {
    echo "Hard-stopping existing cpuminer processes..."
    rm -rf "$LOG_DIR"/cpuminer*.log
    shopt -s nullglob
    for pidfile in "$PID_DIR"/*.pid; do
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        [ -n "${pid:-}" ] || { rm -f "$pidfile"; continue; }
        if [ -d "/proc/$pid" ]; then
            if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "cpuminer"; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
        rm -f "$pidfile"
    done
    shopt -u nullglob
}

# ====== Extra args ======
# May already be populated from CUSTOM_USER_CONFIG; don't clobber.
if [ -z "${EXTRA_MINER_ARGS+x}" ]; then
    EXTRA_MINER_ARGS=()
fi
if [ -n "${MINER_EXTRA_ARGS:-}" ]; then
    read -ra EXTRA_MINER_ARGS <<< "$MINER_EXTRA_ARGS"
fi

# ====== Launch ======
# civiclight: one process PER NUMA NODE, each locked to that node's CPU list via
# taskset.  --cache-fit then self-selects threads within the node's affinity mask
# and pins them to that node's L3 groups.  Each instance binds its own API port
# (API_PORT_BASE + node) so h-stats.sh can query per-node stats.
#   NUM_THREADS_PER_INSTANCE: if set (not "auto"), passed as -t to EACH node
#     instance (per-node thread count).
THREAD_ARG=""
if [[ "$NUM_THREADS_PER_INSTANCE" != "auto" ]]; then
    THREAD_ARG="-t ${NUM_THREADS_PER_INSTANCE}"
fi
API_PORT_BASE="${API_PORT_BASE:-4048}"

hard_kill_miners

# Collect per-CCD (L3 group) core lists, sized to fit the working set in L3.
# Each CCD gets its own isolated process, taskset-locked to that CCD's physical
# cores, with -t capped to fit CACHE_FIT_MB per thread in the CCD's L3.
# Falls back to per-NUMA-node if CCD detection fails.
#
# LOCK_MODE selects the pinning granularity:
#   ccd  (default) - one instance per CCD/L3 group, threads capped to fit the
#                    4 MB working set in that CCD's L3.  Optimal on dense CCDs
#                    (4-8 cores/CCD: 7742, 5950X) where each slice is
#                    saturated by its own cores.
#   numa           - one instance per NUMA node, threads = node's physical cores, OS
#                   scheduler free to spread across the node's CCDs.  Better on
#                   sparse CCDs (2 cores/CCD, e.g. EPYC 7532) where a 2-core
#                   CCD does NOT saturate its L3 slice and CCD-locking wastes the
#                   node's aggregate L3 bandwidth.  Measured +13% on 7532
#                   (31.7 -> 35.8 kH/s).
LOCK_MODE="${LOCK_MODE:-ccd}"
declare -a NODE_CPULISTS=()
declare -a NODE_THREADS=()

if command -v jq >/dev/null 2>&1; then :; fi  # jq not required here

# Try CCD detection first (finest granularity, best L3 fit) unless LOCK_MODE=numa.
if [[ "$LOCK_MODE" != "numa" ]] && CCDS=$(detect_ccds); then
    while IFS='|' read -r sz phys fulllist; do
        [ -n "$phys" ] || continue
        NODE_CPULISTS+=("$fulllist")
        # Threads per CCD = floor(L3_kb / (CACHE_FIT_MB * 1024)), capped by phys cores.
        if [ "$sz" -gt 0 ]; then
            fit=$(( sz / (CACHE_FIT_MB * 1024) ))
            np=$(echo "$phys" | tr ',' '\n' | wc -l)
            [ "$fit" -gt "$np" ] && fit=$np
            [ "$fit" -lt 1 ] && fit=1
            NODE_THREADS+=("$fit")
        else
            NODE_THREADS+=("")
        fi
    done <<< "$CCDS"
fi

# Per-NUMA-node instances (LOCK_MODE=numa, or no CCDs found).
if [ ${#NODE_CPULISTS[@]} -eq 0 ]; then
    for ((node=0; node<NUMA_NODE_COUNT; node++)); do
        phys=$(numa_node_phys_cpus "$node")
        [ -n "$phys" ] && NODE_CPULISTS+=("$(echo "$phys" | tr ' ' ',' | sed 's/,$//')")
        NODE_THREADS+=("")
    done
fi
# Last-resort fallback: single instance on all physical cores.
if [ ${#NODE_CPULISTS[@]} -eq 0 ]; then
    NODE_CPULISTS=( "0-$(($(nproc)/2-1))" )
    NODE_THREADS=( "" )
fi

NUM_NODES="${#NODE_CPULISTS[@]}"
INST_ID="$(date +%s)"
echo "Launching ${NUM_NODES} civiclight instance(s), lock-mode=${LOCK_MODE} (cache-fit=${CACHE_FIT_MB}MB, pool=${POOL_ADDRESS})..."

NODE_INDEX=0
for node_cpus in "${NODE_CPULISTS[@]}"; do
    port=$((API_PORT_BASE + NODE_INDEX))
    # Per-CCD thread cap if we detected L3; else fall back to NUM_THREADS_PER_INSTANCE / auto.
    ccd_thread_arg=""
    if [ -n "${NODE_THREADS[$NODE_INDEX]}" ]; then
        ccd_thread_arg="-t ${NODE_THREADS[$NODE_INDEX]}"
    elif [[ "$NUM_THREADS_PER_INSTANCE" != "auto" ]]; then
        ccd_thread_arg="-t ${NUM_THREADS_PER_INSTANCE}"
    fi
    CMD=( env nice -n 10 ionice -c2 -n7 taskset -c "$node_cpus" \
          "$CPUMINER_PATH" -a "$ALGO" \
          -o "$POOL_ADDRESS" -u "$mining_address.$rig_name" \
          -b "$port" --cache-fit="$CACHE_FIT_MB" ${ccd_thread_arg} )
    if [ ${#EXTRA_MINER_ARGS[@]} -gt 0 ]; then
        CMD+=( "${EXTRA_MINER_ARGS[@]}" )
    fi

    echo "  ccd ${NODE_INDEX} (cpus ${node_cpus}, api :${port}): ${CMD[*]}"
    "${CMD[@]}" > "$LOG_DIR/cpuminer${INST_ID}_node${NODE_INDEX}.log" 2>&1 &
    MINER_PID=$!
    echo "$MINER_PID" > "$PID_DIR/cpu${INST_ID}_node${NODE_INDEX}.pid"
    echo "  ccd ${NODE_INDEX} PID: $MINER_PID"
    NODE_INDEX=$((NODE_INDEX + 1))
done

echo "CivicLight miner launched (${NUM_NODES} instances). Waiting (HiveOS handles restarts)..."
# Wait on all instance PIDs.
for pidfile in "$PID_DIR"/cpu${INST_ID}_node*.pid; do
    [ -f "$pidfile" ] || continue
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    [ -n "$pid" ] && { wait "$pid" 2>/dev/null || true; }
done
exit 0
