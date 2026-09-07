#!/usr/bin/env bash
# h-run.sh — HiveOS entrypoint for cpuminer-opt-cpupower (civiclight).
# Thin wrapper (tequila pattern): sources miner_env.conf, then execs cpuminer.sh
# which does topology detection, per-node hugepage sizing, and --cache-fit launch.
echo "=== h-run.sh starting ==="
echo "PWD: $(pwd)"

if [ ! -f "h-manifest.conf" ]; then
    echo "ERROR: h-manifest.conf not found in $(pwd)"
    exit 1
fi
source h-manifest.conf

CUSTOM_LOG_BASEDIR=`dirname "$CUSTOM_LOG_BASENAME"`
[[ ! -d $CUSTOM_LOG_BASEDIR ]] && mkdir -p $CUSTOM_LOG_BASEDIR

if [[ -z $CUSTOM_CONFIG_FILENAME ]]; then
    echo -e "ERROR: The config file is not defined (CUSTOM_CONFIG_FILENAME is empty)"
    exit 1
fi

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/hive/lib

# Source miner environment variables
ENV_FILE="${CUSTOM_CONFIG_BASENAME}/miner_env.conf"
if [ -f "$ENV_FILE" ]; then
    echo "Loading miner environment from: $ENV_FILE"
    source "$ENV_FILE"
fi

echo $(date +%s) > "/tmp/miner_start_time"
echo "Starting cpuminer.sh..."
/hive/miners/custom/cpuminer/cpuminer.sh
EXIT_CODE=$?
echo "Miner has exited with code: $EXIT_CODE"
exit $EXIT_CODE
