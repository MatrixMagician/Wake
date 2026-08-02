#!/usr/bin/env bash
# Measure Wake's overhead against the SPEC.md §3 budget and record the result.
#
# The budget is < 1% CPU and < 128 MiB RSS at 10k events/s sustained. This
# script turns that sentence into a number, and exits non-zero when the number
# is wrong, so that it can gate a release.
set -euo pipefail

RATE=${RATE:-10000}
DURATION=${DURATION:-60}
CPU_BUDGET=${CPU_BUDGET:-1.0}
RSS_BUDGET_MB=${RSS_BUDGET_MB:-128}
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONFIG=${CONFIG:-$REPO_ROOT/deploy/wake.example.toml}

if [[ $EUID -ne 0 ]]; then
  echo "This must run as root: it loads BPF programs." >&2
  exit 1
fi

cd "$REPO_ROOT"
echo "Building..."
make build >/dev/null

echo "Starting the recorder..."
./wake run --config "$CONFIG" --log-level warn &
WAKE_PID=$!
trap 'kill $WAKE_PID 2>/dev/null || true' EXIT
sleep 3

if ! kill -0 $WAKE_PID 2>/dev/null; then
  echo "The recorder exited during start-up; run 'wake doctor'." >&2
  exit 1
fi

# Baseline CPU, so the measurement is Wake's own cost rather than whatever the
# box was already doing.
read -r -a STAT_0 < /proc/$WAKE_PID/stat
HZ=$(getconf CLK_TCK)
UTIME_0=${STAT_0[13]}; STIME_0=${STAT_0[14]}

echo "Generating ${RATE} events/s for ${DURATION}s..."
go run -tags loadgen ./testdata/loadgen/loadgen.go -rate "$RATE" -duration "${DURATION}s"

read -r -a STAT_1 < /proc/$WAKE_PID/stat
UTIME_1=${STAT_1[13]}; STIME_1=${STAT_1[14]}
RSS_KB=$(awk '/VmRSS/ {print $2}' /proc/$WAKE_PID/status)

CPU_SEC=$(echo "scale=4; ($UTIME_1 + $STIME_1 - $UTIME_0 - $STIME_0) / $HZ" | bc)
CPU_PCT=$(echo "scale=3; 100 * $CPU_SEC / $DURATION" | bc)
RSS_MB=$(echo "scale=1; $RSS_KB / 1024" | bc)

echo
echo "=== Overhead at ${RATE} events/s over ${DURATION}s ==="
echo "CPU: ${CPU_PCT}% (budget ${CPU_BUDGET}%)"
echo "RSS: ${RSS_MB} MiB (budget ${RSS_BUDGET_MB} MiB)"
echo
echo "Drop accounting:"
./wake status 2>/dev/null | sed -n '/Drops:/,/^$/p' || true

FAIL=0
if (( $(echo "$CPU_PCT > $CPU_BUDGET" | bc) )); then
  echo "FAIL: CPU over budget"; FAIL=1
fi
if (( $(echo "$RSS_MB > $RSS_BUDGET_MB" | bc) )); then
  echo "FAIL: RSS over budget"; FAIL=1
fi

{
  echo
  echo "## $(date -Is) — kernel $(uname -r)"
  echo
  echo "| Metric | Measured | Budget |"
  echo "|---|---|---|"
  echo "| CPU at ${RATE} ev/s | ${CPU_PCT}% | ${CPU_BUDGET}% |"
  echo "| RSS | ${RSS_MB} MiB | ${RSS_BUDGET_MB} MiB |"
} >> "$REPO_ROOT/docs/perf.md"

exit $FAIL
