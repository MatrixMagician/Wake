#!/usr/bin/env bash
# End-to-end smoke test: start the daemon, exercise every control command,
# and assert the snapshot is well-formed. Run as root.
set -uo pipefail
cd "$(dirname "$0")/.."

SOCK=/tmp/wake-smoke.sock
DIR=/tmp/wake-smoke-snapshots
CFG=/tmp/wake-smoke.toml

# Match on the config path, which is what actually appears on the command line.
# An almost-right pattern here leaks a BPF-loading daemon on every run, which is
# a slow, quiet way to fill a developer's machine.
cleanup() { pkill -f "wake run --config $CFG" 2>/dev/null; }
trap cleanup EXIT
cleanup; sleep 1
rm -rf "$DIR" "$SOCK"

cat > "$CFG" <<TOML
[classes]
exec = true
exit = true
signal = false
oom = true
open = false
connect = false

[ring]
window = "5m"
max_events = 50000
memory_budget_bytes = 67108864

[snapshot]
dir = "$DIR"
retention_count = 5

[triggers.manual]
enabled = true
cooldown = "0s"

[[triggers.watched_process]]
name = "smoke-victim"
comm_glob = "sleep"
exit_code = "nonzero"
cooldown = "1s"

[redaction]
use_default_rules = true
TOML

fail() { echo "FAIL: $*"; exit 1; }
ok()   { echo "ok: $*"; }

./wake verify-config "$CFG" >/dev/null || fail "verify-config rejected the smoke config"
ok "verify-config"

./wake run --config "$CFG" --socket "$SOCK" --log-level info > /tmp/wake-smoke.log 2>&1 &
WAKE=$!
sleep 4
kill -0 $WAKE 2>/dev/null || { cat /tmp/wake-smoke.log; fail "daemon died during start-up"; }
ok "daemon started"

# Manual trigger must report the path it actually wrote.
OUT=$(./wake trigger --socket "$SOCK" --reason "smoke test")
echo "$OUT" | grep -q "$DIR" || fail "trigger did not report a real path: $OUT"
ok "manual trigger: $OUT"

# A watched process dying must fire its rule.
sleep 1
(sleep 30 & echo $! > /tmp/wake-smoke.pid); sleep 1
kill -TERM "$(cat /tmp/wake-smoke.pid)" 2>/dev/null
sleep 2
grep -q "smoke-victim" /tmp/wake-smoke.log || fail "the watched-process trigger never fired"
ok "watched-process trigger fired"

# Status must be answerable and must report drops.
./wake status --socket "$SOCK" | grep -q "Drops:" || fail "status does not report drops"
ok "status reports drops"

# Watch must stream the same JSONL a snapshot contains.
timeout 3 ./wake watch --socket "$SOCK" --class exec > /tmp/wake-smoke-watch.out 2>&1 &
sleep 1; /bin/echo smoke-probe > /dev/null; sleep 3
grep -q '"class":"exec"' /tmp/wake-smoke-watch.out || fail "watch produced no exec events"
ok "watch streams events"

# The snapshot must be complete and 0700.
SNAP=$(find "$DIR" -maxdepth 1 -mindepth 1 -type d | head -1)
[[ -n "$SNAP" ]] || fail "no snapshot directory"
for f in manifest.json events.jsonl.zst system.json; do
  [[ -f "$SNAP/$f" ]] || fail "snapshot is missing $f"
done
ok "snapshot contains manifest, events and system info"

PERM=$(stat -c %a "$SNAP")
[[ "$PERM" == "700" ]] || fail "snapshot is mode $PERM, not 700 (privacy line)"
ok "snapshot is 0700"

python3 -c "
import json,sys
m=json.load(open('$SNAP/manifest.json'))
for k in ('schema_version','wake_version','trigger','drops','config_hash','event_count'):
    assert k in m, 'manifest is missing '+k
assert m['trigger']['reason'], 'trigger carries no reason'
for boundary in ('kernel_ringbuf','decode','userspace_ring','watch_fanout'):
    assert boundary in m['drops'], 'drop report is missing '+boundary
print('ok: manifest is complete, all four drop boundaries reported')
" || fail "manifest validation"

./wake snapshots list --dir "$DIR" | grep -q . || fail "snapshots list is empty"
ok "snapshots list"

# Exit codes are this command's whole contract: provisioning gates on them.
./wake verify-config "$CFG" >/dev/null 2>&1 || fail "verify-config rejected a valid config"
./wake verify-config /nonexistent-wake.toml >/dev/null 2>&1 && fail "verify-config accepted a missing file"
printf '[ring]\nwindow = "0s"\nmax_events = 0\nmemory_budget_bytes = 0\n' > /tmp/wake-smoke-bad.toml
./wake verify-config /tmp/wake-smoke-bad.toml >/dev/null 2>&1 && fail "verify-config accepted an unbounded ring"
ok "verify-config is exit-code gated"

# prune must actually delete, and must not delete without --yes.
BEFORE=$(find "$DIR" -maxdepth 1 -mindepth 1 -type d | wc -l)
./wake snapshots prune --dir "$DIR" --keep 1 >/dev/null
AFTER_DRY=$(find "$DIR" -maxdepth 1 -mindepth 1 -type d | wc -l)
[[ "$BEFORE" == "$AFTER_DRY" ]] || fail "prune deleted without --yes"
./wake snapshots prune --dir "$DIR" --keep 1 --yes >/dev/null
AFTER=$(find "$DIR" -maxdepth 1 -mindepth 1 -type d | wc -l)
[[ "$AFTER" -le 1 ]] || fail "prune --yes did not delete ($AFTER remain)"
ok "prune deletes only with --yes"

grep -Ei "fatal error|^panic:" /tmp/wake-smoke.log && fail "the daemon panicked"
ok "no panics"

cleanup
sleep 1
if pgrep -f "wake run --config $CFG" >/dev/null 2>&1; then
  fail "the smoke test leaked a daemon; its cleanup pattern no longer matches"
fi
ok "no leaked daemons"

echo
echo "ALL SMOKE CHECKS PASSED"
