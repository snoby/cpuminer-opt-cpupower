#!/usr/bin/env bash
set -euo pipefail

# cpuminer-opt-cpupower HiveOS stats collector.
#
# Queries the miner's HTTP JSON API (/api/stats) on one or more endpoints and
# emits HiveOS stats JSON. Unlike the older raw-TCP API wrapper, this uses the
# HTTP route so it works with any HTTP client (curl) and returns richer JSON.
#
# Default endpoints match the per-CCD/per-NUMA instance behavior of cpuminer.sh:
# one instance per L3 group, each on API_PORT_BASE + index (4048, 4049, ...).
# The instance count varies with topology (2 per-NUMA nodes, or 16 per-CCD on a
# 7742), so instead of assuming a fixed count we AUTO-DISCOVER live instances by
# probing a port range and keeping only those that answer. API_ENDPOINTS can still be
# overridden explicitly via the flight-sheet Custom config.
API_PORT_BASE="${API_PORT_BASE:-4048}"
# Upper bound of the probe range (generous: covers up to 64 CCD instances).
API_PROBE_RANGE="${API_PROBE_RANGE:-64}"
API_ENDPOINTS="${API_ENDPOINTS:-}"
if [ -z "$API_ENDPOINTS" ]; then
    API_ENDPOINTS=""
    for ((i=0; i<API_PROBE_RANGE; i++)); do
        port=$((API_PORT_BASE + i))
        if curl -s --max-time 1 -o /dev/null "http://127.0.0.1:${port}/api/stats" 2>/dev/null; then
            API_ENDPOINTS="$API_ENDPOINTS 127.0.0.1:$port"
        fi
    done
    # Fall back to a single endpoint if nothing responded yet (startup race).
    [ -z "$API_ENDPOINTS" ] && API_ENDPOINTS="127.0.0.1:$API_PORT_BASE"
fi

fetch_stats() {
  local endpoint="$1"
  local host="${endpoint%:*}"
  local port="${endpoint##*:}"
  curl -s --max-time 2 "http://${host}:${port}/api/stats" 2>/dev/null || true
}

num_or_zero() {
  local v="${1:-}"
  if [[ "$v" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
    printf '%s' "$v"
  else
    printf '0'
  fi
}

hs_arr="[]"
temp_arr="[]"
fan_arr="[]"
bus_arr="[]"

khs_total="0"
acc_total=0
rej_total=0
uptime_max=0
algo="unknown"
ver="cpuminer-opt"

have_data=0
for ep in $API_ENDPOINTS; do
  json=$(fetch_stats "$ep")
  [[ -n "${json:-}" ]] || continue

  # Validate it parses as JSON with a hashrate field.
  if ! jq -e '.hashrate' >/dev/null 2>&1 <<<"$json"; then
    continue
  fi
  have_data=1

  name=$(jq -r '.name // empty' <<<"$json")
  ver_raw=$(jq -r '.version // empty' <<<"$json")
  algo_raw=$(jq -r '.algo // empty' <<<"$json")
  hr=$(num_or_zero "$(jq -r '.hashrate // 0' <<<"$json")")
  khs=$(num_or_zero "$(jq -r '.hashrate_khs // 0' <<<"$json")")
  acc=$(num_or_zero "$(jq -r '.accepted // 0' <<<"$json")")
  rej=$(num_or_zero "$(jq -r '.rejected // 0' <<<"$json")")
  temp=$(num_or_zero "$(jq -r '.temp // 0' <<<"$json")")
  fan=$(num_or_zero "$(jq -r '.fan_percent // 0' <<<"$json")")
  up=$(num_or_zero "$(jq -r '.uptime_sec // 0' <<<"$json")")

  [[ -n "$name" && -n "$ver_raw" ]] && ver="${name}-${ver_raw}"
  [[ -n "$algo_raw" ]] && algo="$algo_raw"

  # Fallback: derive KHS from raw hashrate if hashrate_khs missing/zero.
  if [[ "$khs" == "0" && "$hr" != "0" ]]; then
    khs=$(awk -v v="$hr" 'BEGIN{printf "%.4f", v/1000.0}')
  fi

  khs_total=$(awk -v a="$khs_total" -v b="$khs" 'BEGIN{printf "%.4f", a+b}')
  acc_total=$((acc_total + ${acc%%.*}))
  rej_total=$((rej_total + ${rej%%.*}))
  # uptime is a float (e.g. 107.0); truncate to integer before arithmetic compare.
  up_int=${up%%.*}
  [[ -z "$up_int" ]] && up_int=0
  (( up_int > uptime_max )) && uptime_max=$up_int

  # Store per-device hashrate in KH units to match hs_units:khs (HiveOS scales
  # hs[] by 1000 to recover raw H/s).  hr is raw H/s.
  hr_khs=$(awk -v v="$hr" 'BEGIN{printf "%.4f", v/1000.0}')
  hs_arr=$(jq -c --argjson v "$hr_khs" '. + [$v]' <<<"$hs_arr")
  temp_arr=$(jq -c --argjson v "$temp" '. + [$v]' <<<"$temp_arr")
  fan_arr=$(jq -c --argjson v "$fan" '. + [$v]' <<<"$fan_arr")
  bus_arr=$(jq -c '. + [null]' <<<"$bus_arr")
done

if [[ "$have_data" -eq 0 ]]; then
  # Hive expects valid JSON even during startup.  Assign to $stats (the agent
  # sources this script and reads the $stats / $khs shell variables).
  khs=0
  stats=$(jq -nc \
    --argjson khs 0 \
    --argjson total_khs 0 \
    --arg hs_units 'khs' \
    --argjson hs '[0]' \
    --argjson temp '[0]' \
    --argjson fan '[0]' \
    --argjson uptime 0 \
    --arg ver 'cpuminer-opt' \
    --arg algo 'unknown' \
    --argjson bus_numbers '[null]' \
    '{khs:$khs, total_khs:$total_khs, hs_units:$hs_units, hs:$hs, temp:$temp, fan:$fan, uptime:$uptime, ver:$ver, ar:[0,0], algo:$algo, bus_numbers:$bus_numbers}')
  echo "$stats"
  exit 0
fi

# HiveOS agent reads $khs (in KH units) and $stats after sourcing this script.
khs="$khs_total"
export khs

stats=$(jq -nc \
  --argjson khs "$khs_total" \
  --argjson total_khs "$khs_total" \
  --arg hs_units 'khs' \
  --argjson hs "$hs_arr" \
  --argjson temp "$temp_arr" \
  --argjson fan "$fan_arr" \
  --argjson uptime "$uptime_max" \
  --arg ver "$ver" \
  --argjson acc "$acc_total" \
  --argjson rej "$rej_total" \
  --arg algo "$algo" \
  --argjson bus_numbers "$bus_arr" \
  '{khs:$khs, total_khs:$total_khs, hs_units:$hs_units, hs:$hs, temp:$temp, fan:$fan, uptime:$uptime, ver:$ver, ar:[$acc,$rej], algo:$algo, bus_numbers:$bus_numbers}')

echo "$stats"
