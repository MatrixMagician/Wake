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
| `ProtectKernelTunables` | `no` | Wake reads `/sys/kernel/btf/vmlinux` for CO-RE and `/sys/kernel/tracing/events/*/format` to verify tracepoint layouts. Both live under the tree this option hides. Verifying layouts against the running kernel is a hard requirement (SPEC.md §8), so this option cannot be enabled. |
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
- `systemd-analyze security wake.service` scores **3.8 (OK)**. Its remaining
  complaints are the settings listed above, each of which is load-bearing.

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
