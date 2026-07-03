#!/bin/bash
# mine-rplant.sh — launch yespower mining on rplant.xyz
#
# Wraps mine-yespower.sh with the pool/wallet already filled in.
# Pass any extra flags through (e.g. -t, -n for dry run).

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

ADDRESS="RPjTUj8ixSSwPBY95SU6D2xtL3dWcqgVTL"
POOL_URL="stratum+ssl://na.rplant.xyz:17122"
POOL_USER="${ADDRESS}.ethpow"

exec "$DIR/mine-yespower.sh" \
    -a yespower \
    -o "$POOL_URL" \
    -u "$POOL_USER" \
    "$@"
