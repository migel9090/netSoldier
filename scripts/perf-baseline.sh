#!/usr/bin/env bash
# Performance baseline benchmark for netSoldier services.
# Run on Pi 3B+ or server to establish throughput / latency / resource limits.
#
# Prerequisites: services running locally or port-forwarded.
#   DET_ADDR  — detection-engine  (default 127.0.0.1:8080)
#   INV_ADDR  — device-inventory  (default 127.0.0.1:8081)
#   KS_ADDR   — killswitch-ctrl   (default 127.0.0.1:8084)
#   DURATION  — seconds per test  (default 30)
#   CONCURRENCY — parallel clients (default 4)
#
# Output: perf-baseline-<hostname>-<date>.json

set -euo pipefail

DET_ADDR="${DET_ADDR:-127.0.0.1:8080}"
INV_ADDR="${INV_ADDR:-127.0.0.1:8081}"
KS_ADDR="${KS_ADDR:-127.0.0.1:8084}"
DURATION="${DURATION:-30}"
CONCURRENCY="${CONCURRENCY:-4}"

OUTFILE="perf-baseline-$(hostname)-$(date +%Y%m%d-%H%M%S).json"

command -v curl >/dev/null  || { echo "curl required"; exit 1; }

# ── Helpers ──────────────────────────────────────────────────────────

get_system_info() {
  local arch cpu_model cpu_cores mem_total_kb mem_total_mb throttled=""
  arch=$(uname -m)
  cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "unknown")
  cpu_cores=$(nproc 2>/dev/null || echo "?")
  mem_total_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
  mem_total_mb=$((mem_total_kb / 1024))

  if command -v vcgencmd >/dev/null 2>&1; then
    throttled=$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2 || echo "n/a")
  fi

  cat <<JSON
  "system": {
    "hostname": "$(hostname)",
    "arch": "${arch}",
    "cpu_model": "${cpu_model}",
    "cpu_cores": ${cpu_cores},
    "memory_mb": ${mem_total_mb},
    "kernel": "$(uname -r)",
    "throttled_flag": "${throttled:-n/a}"
  }
JSON
}

check_health() {
  local name=$1 url=$2
  local code latency_ms
  code=$(curl -sf -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || echo "000")
  latency_ms=$(curl -sf -o /dev/null -w '%{time_total}' --max-time 5 "$url" 2>/dev/null || echo "0")
  latency_ms=$(echo "$latency_ms * 1000" | bc 2>/dev/null || echo "0")
  echo "  { \"service\": \"${name}\", \"status\": ${code}, \"latency_ms\": ${latency_ms%.*} }"
}

http_bench() {
  local name=$1 method=$2 url=$3 body=$4
  local total=0 success=0 fail=0 min_ms=999999 max_ms=0 sum_ms=0
  local end_time=$(($(date +%s) + DURATION))
  local pids=()

  tmpdir=$(mktemp -d)
  trap "rm -rf $tmpdir" RETURN

  for c in $(seq 1 "$CONCURRENCY"); do
    (
      local ltotal=0 lsuccess=0 lfail=0 lmin=999999 lmax=0 lsum=0
      while [ "$(date +%s)" -lt "$end_time" ]; do
        local t_ms
        if [ "$method" = "GET" ]; then
          t_ms=$(curl -sf -o /dev/null -w '%{time_total}' --max-time 5 "$url" 2>/dev/null || echo "-1")
        else
          t_ms=$(curl -sf -o /dev/null -w '%{time_total}' --max-time 5 \
            -X POST -H 'Content-Type: application/json' -d "$body" "$url" 2>/dev/null || echo "-1")
        fi
        ltotal=$((ltotal + 1))
        if [ "$t_ms" != "-1" ]; then
          lsuccess=$((lsuccess + 1))
          local ms
          ms=$(echo "$t_ms * 1000" | bc 2>/dev/null || echo "0")
          ms=${ms%.*}
          lsum=$((lsum + ms))
          [ "$ms" -lt "$lmin" ] 2>/dev/null && lmin=$ms
          [ "$ms" -gt "$lmax" ] 2>/dev/null && lmax=$ms
        else
          lfail=$((lfail + 1))
        fi
      done
      echo "${ltotal} ${lsuccess} ${lfail} ${lmin} ${lmax} ${lsum}" > "${tmpdir}/${c}.txt"
    ) &
    pids+=($!)
  done

  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  for f in "${tmpdir}"/*.txt; do
    read -r lt ls lf lmin lmax lsum < "$f"
    total=$((total + lt))
    success=$((success + ls))
    fail=$((fail + lf))
    sum_ms=$((sum_ms + lsum))
    [ "$lmin" -lt "$min_ms" ] 2>/dev/null && min_ms=$lmin
    [ "$lmax" -gt "$max_ms" ] 2>/dev/null && max_ms=$lmax
  done

  local avg_ms=0 rps=0 drop_pct=0
  [ "$success" -gt 0 ] && avg_ms=$((sum_ms / success))
  [ "$DURATION" -gt 0 ] && rps=$((total / DURATION))
  [ "$total" -gt 0 ] && drop_pct=$((fail * 100 / total))

  cat <<JSON
  {
    "test": "${name}",
    "method": "${method}",
    "duration_s": ${DURATION},
    "concurrency": ${CONCURRENCY},
    "total_requests": ${total},
    "success": ${success},
    "failed": ${fail},
    "drop_rate_pct": ${drop_pct},
    "rps": ${rps},
    "latency_ms": { "min": ${min_ms}, "avg": ${avg_ms}, "max": ${max_ms} }
  }
JSON
}

measure_proc_resources() {
  local name=$1 pattern=$2
  local pid rss_kb cpu
  pid=$(pgrep -f "$pattern" 2>/dev/null | head -1 || echo "")
  if [ -n "$pid" ]; then
    rss_kb=$(ps -o rss= -p "$pid" 2>/dev/null | xargs || echo "0")
    cpu=$(ps -o %cpu= -p "$pid" 2>/dev/null | xargs || echo "0")
    echo "  { \"service\": \"${name}\", \"pid\": ${pid}, \"rss_mb\": $((rss_kb / 1024)), \"cpu_pct\": ${cpu} }"
  else
    echo "  { \"service\": \"${name}\", \"pid\": null, \"rss_mb\": 0, \"cpu_pct\": 0 }"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────

echo "netSoldier performance baseline"
echo "  host:        $(hostname)"
echo "  duration:    ${DURATION}s per test"
echo "  concurrency: ${CONCURRENCY}"
echo ""

echo "Checking service health..."
det_ok=$(curl -sf -o /dev/null -w '%{http_code}' --max-time 5 "http://${DET_ADDR}/healthz" 2>/dev/null || echo "000")
inv_ok=$(curl -sf -o /dev/null -w '%{http_code}' --max-time 5 "http://${INV_ADDR}/healthz" 2>/dev/null || echo "000")
ks_ok=$(curl -sf -o /dev/null -w '%{http_code}' --max-time 5 "http://${KS_ADDR}/healthz"  2>/dev/null || echo "000")

echo "  detection-engine:     ${det_ok}"
echo "  device-inventory:     ${inv_ok}"
echo "  killswitch-controller: ${ks_ok}"
echo ""

EVAL_BODY='{"schema_version":"1.0","id":"PERF-BENCH","domain":"bench.example.com","matched_ioc":"bench.example.com","ioc_type":"domain","client_ip":"10.0.0.1","severity":"low","confidence":10,"source":"perf-baseline"}'

results="["

echo "==> [1/${CONCURRENCY}c × ${DURATION}s] GET /healthz (detection-engine)"
r=$(http_bench "det-healthz" "GET" "http://${DET_ADDR}/healthz" "")
results="${results}${r},"

echo "==> [2/${CONCURRENCY}c × ${DURATION}s] GET /alerts (detection-engine)"
r=$(http_bench "det-alerts" "GET" "http://${DET_ADDR}/alerts" "")
results="${results}${r},"

echo "==> [3/${CONCURRENCY}c × ${DURATION}s] GET /healthz (device-inventory)"
r=$(http_bench "inv-healthz" "GET" "http://${INV_ADDR}/healthz" "")
results="${results}${r},"

echo "==> [4/${CONCURRENCY}c × ${DURATION}s] GET /devices (device-inventory)"
r=$(http_bench "inv-devices" "GET" "http://${INV_ADDR}/devices" "")
results="${results}${r},"

echo "==> [5/${CONCURRENCY}c × ${DURATION}s] GET /healthz (killswitch)"
r=$(http_bench "ks-healthz" "GET" "http://${KS_ADDR}/healthz" "")
results="${results}${r},"

echo "==> [6/${CONCURRENCY}c × ${DURATION}s] POST /evaluate (killswitch — ignore)"
r=$(http_bench "ks-evaluate-ignore" "POST" "http://${KS_ADDR}/evaluate" "$EVAL_BODY")
results="${results}${r}"

results="${results}]"

echo ""
echo "Collecting resource snapshots..."

resources="["
resources="${resources}$(measure_proc_resources "detection-engine" "detection-engine"),"
resources="${resources}$(measure_proc_resources "device-inventory" "device-inventory"),"
resources="${resources}$(measure_proc_resources "killswitch-controller" "killswitch-controller")"
resources="${resources}]"

health="["
health="${health}$(check_health "detection-engine" "http://${DET_ADDR}/healthz"),"
health="${health}$(check_health "device-inventory" "http://${INV_ADDR}/healthz"),"
health="${health}$(check_health "killswitch-controller" "http://${KS_ADDR}/healthz")"
health="${health}]"

cat > "$OUTFILE" <<JSON
{
$(get_system_info),
  "config": {
    "duration_s": ${DURATION},
    "concurrency": ${CONCURRENCY},
    "date": "$(date -Iseconds)"
  },
  "health": ${health},
  "benchmarks": ${results},
  "resources_snapshot": ${resources}
}
JSON

echo ""
echo "Results written to: ${OUTFILE}"
echo ""

echo "── Summary ────────────────────────────────────────────────────"
echo ""
printf "%-25s %8s %8s %8s %8s %6s\n" "Test" "RPS" "Avg(ms)" "Max(ms)" "Total" "Drop%"
printf "%-25s %8s %8s %8s %8s %6s\n" "-------------------------" "--------" "--------" "--------" "--------" "------"

echo "$results" | grep -oP '"test":\s*"\K[^"]+' | while read -r test_name; do
  rps=$(echo "$results" | grep -A10 "\"$test_name\"" | grep -oP '"rps":\s*\K[0-9]+' | head -1)
  avg=$(echo "$results" | grep -A10 "\"$test_name\"" | grep -oP '"avg":\s*\K[0-9]+' | head -1)
  max=$(echo "$results" | grep -A10 "\"$test_name\"" | grep -oP '"max":\s*\K[0-9]+' | head -1)
  tot=$(echo "$results" | grep -A10 "\"$test_name\"" | grep -oP '"total_requests":\s*\K[0-9]+' | head -1)
  drp=$(echo "$results" | grep -A10 "\"$test_name\"" | grep -oP '"drop_rate_pct":\s*\K[0-9]+' | head -1)
  printf "%-25s %8s %8s %8s %8s %5s%%\n" "$test_name" "$rps" "$avg" "$max" "$tot" "$drp"
done

echo ""
echo "Run on both pi-edge and proxmox-soc to populate docs/performance-baseline.md"
