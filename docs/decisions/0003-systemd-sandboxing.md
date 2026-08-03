# 0003. systemd sandboxing options that had to be loosened

## Status

Accepted.

## Context

SPEC.md §3 requires a hardened systemd unit (`ProtectSystem=strict`,
`NoNewPrivileges`, restricted `ReadWritePaths`), and SPEC.md M6 requires that
we document what had to be loosened and why, on the grounds that "sandboxing
options and BPF interact non-obviously".

Starting from a maximally hardened unit and removing options until the daemon
worked produced a short, specific list. Each entry below is a setting that
`systemd-analyze security` would like us to enable and that we deliberately do
not.

## Decision

The following are set permissively, each for a load-bearing reason:

| Setting | Value | Why |
|---|---|---|
| `ProtectKernelTunables` | `no` | Wake reads `/sys/kernel/btf/vmlinux` for CO-RE and `/sys/kernel/tracing/events/*/format` to verify tracepoint layouts. Both live under the tree this option hides. Verifying layouts against the running kernel is a hard requirement (SPEC.md §9), so this option cannot be enabled. |
| `ProtectProc` | `default` | The snapshot's `proc/` scrape reads `/proc/<pid>/{status,limits,cgroup,fdinfo}` for a process owned by another user. `ProtectProc=invisible` hides exactly those. Half a snapshot's value is that scrape. |
| `MemoryDenyWriteExecute` | `no` | `cilium/ebpf` maps program images writable before submitting them to the verifier. With W^X enforced, every program load fails. |
| `SystemCallFilter` | `@system-service bpf perf_event_open` | `@system-service` deliberately excludes `bpf(2)` and `perf_event_open(2)`. Both must be added back explicitly; without them the daemon cannot load a single program. This is the most common way to break the unit while "hardening" it. |
| `PrivateUsers` | `no` | BPF loading requires capabilities in the initial user namespace. |

The following remain hardened, having proved compatible:
`ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`,
`ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `RestrictNamespaces=yes`,
`RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`,
`PrivateTmp=yes`, and a capability bounding set of exactly
`CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH`.

`OOMScoreAdjust=-500` is set because Wake is the witness: it should be among
the last processes the OOM killer considers during the very incident it exists
to record.

## Verification

This is not reasoning alone: the unit was installed and the daemon run under it
on the reference box (Fedora 44, kernel 7.1.5-201.fc44.x86_64). Observed:

- All six event classes loaded and attached under the sandbox.
- `wake status` and `wake trigger` worked over the control socket in
  `RuntimeDirectory=wake`.
- A snapshot was written to `StateDirectory=wake` at mode 0700, containing
  `manifest.json`, `events.jsonl.zst` and `system.json`.
- The sd-bus unit-failure trigger fired for a purposely-failing transient unit
  and produced a snapshot, proving the bus subscription survives the sandbox.
- `Type=notify` readiness was accepted; systemd reported the unit active rather
  than timing out.
- `systemd-analyze security wake.service` scored **3.8 (OK)** at the time of
  that run. Its remaining complaints are the settings listed above, each of
  which is load-bearing. (Adding `CAP_SYS_PTRACE` for the reason given below
  moved this to **4.1 (OK)** — a worse score for a strictly more useful tool,
  which is why the score is recorded rather than chased.)

`UMask=0077` was added as a result of that run: `systemd-analyze` flagged the
default, and while the snapshot writer chmods 0700 explicitly, defence in depth
costs nothing here.

## Consequences

- `systemd-analyze security wake.service` will report a middling score. That is
  the correct outcome for a diagnostic tool that must read kernel metadata and
  other processes' `/proc`, and the score should not be chased.
- If a future kernel or `cilium/ebpf` release removes the need for
  `MemoryDenyWriteExecute=no`, that line can be dropped; the integration test
  that runs the daemon under this unit is what would prove it.
- SELinux is orthogonal to all of the above. `wake doctor` reports whether
  SELinux is enforcing and points at `ausearch -m avc`, because a denial there
  looks identical to a capability problem from the daemon's side.

## What the second run found (2026-08-03)

The run recorded above exercised the paths that *fail loudly*: load, attach,
control socket, snapshot write, bus subscription, readiness. It missed two
failures that look exactly like success, both found only by installing the unit
and then reading what came out of it.

**1. Blank fd listings — a missing capability.** `readlink()` on a
`/proc/<pid>/fd/` entry is gated on `PTRACE_MODE_READ`, not on file
permissions, so `CAP_DAC_READ_SEARCH` is not sufficient for it. Without
`CAP_SYS_PTRACE` the scrape still succeeded, `proc/fd_listing.txt` was still
written, and every fd was listed — with an empty target. Nothing errored; the
evidence was simply absent. Isolated by running the same `readlink` under
`systemd-run` with the unit's exact capability set, which failed with `EACCES`,
and again with `CAP_SYS_PTRACE` added, which succeeded. The capability is now
granted, and `wake doctor` has a check that reports the denial with its remedy.

The code was also at fault and is fixed: it rendered *any* failed `readlink` as
an empty string, conflating "fd closed mid-listing" (benign, expected, the
process is racing us) with "permission denied" (a misconfiguration). Both are
now in-band sentinels, so this can never again be invisible in a snapshot.

**2. `systemctl reload` stopped the recorder.** `ExecReload=/bin/kill -HUP
$MAINPID` was declared, but the daemon never handled `SIGHUP`, so the default
disposition applied and it terminated. systemd logged `Reloaded wake.service
successfully` and reported a clean exit. A flight recorder that silently stops
on a routine administrative action is the worst failure mode this project has.

`ExecReload=` is removed rather than implemented: Wake does not reconfigure in
place, because every snapshot records the config hash it was taken under and
swapping config beneath a live ring would make that record a lie. `reload` now
fails with "not applicable" instead of appearing to work. `SIGHUP` is
additionally caught and ignored with a warning, so an inherited hangup from any
other source cannot kill the recorder either.

Both are pinned by tests over the unit file itself
(`internal/cli/unitfile_test.go`), since nothing else type-checks a `.service`.
No SELinux denials were observed on the reference box in either run.

The general lesson: verifying a sandbox by checking that the daemon *starts* is
not verification. The failures worth finding are the ones where everything
reports success and the evidence is quietly missing.
