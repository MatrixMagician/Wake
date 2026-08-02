# Wake

**An eBPF incident flight recorder for Linux.**

Wake records what the kernel saw in the ninety seconds before something died.
It keeps process, file, network, signal and OOM events in a bounded in-memory
ring, writes nothing during normal operation, and persists a self-contained
snapshot only when a trigger fires.

It answers the question logs cannot: applications log what they chose to log,
and the thing that killed them was usually not on the list.

```
wake doctor          # can this host run Wake, and if not, exactly why?
wake run             # the daemon
wake status          # ring occupancy, drops, uptime, active triggers
wake watch           # live decoded tail, same JSONL a snapshot contains
wake trigger         # take a snapshot now
wake snapshots list  # what have we got?
```

## What it is not

Wake is a diagnostic tool for support and reliability engineers, not a security
platform.

- **auditd** captures everything to disk with painful rules. Wake records to
  memory and persists only on trigger.
- **Tetragon, Tracee, Falco** are security observability platforms: policy
  engines, enforcement, fleet scale. Wake is one binary, one host, one job.
- **strace** requires foresight and imposes brutal overhead. Wake is always-on
  at negligible cost.
- **sosreport** captures state *after* the fact. Wake preserves the events
  leading up to it.

## Requirements

- Linux ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux`). Fedora and RHEL ≥ 8.2 ship
  it. See `docs/decisions/0005-minimum-kernel-version.md`.
- Root, or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_RESOURCE`
  (+ `CAP_DAC_READ_SEARCH` for `/proc` scrapes).

Run `wake doctor` first. It is exit-code gated and every failure names its
remedy.

## Install

```bash
make build
sudo install -m 0755 wake /usr/bin/wake
sudo install -Dm 0644 deploy/wake.service /etc/systemd/system/wake.service
sudo install -Dm 0600 deploy/wake.example.toml /etc/wake/wake.toml
sudo wake verify-config /etc/wake/wake.toml
sudo systemctl enable --now wake
```

Building needs Go ≥ 1.26, `clang` and `bpftool` (to dump the build host's BTF).
The resulting binary needs none of them: the BPF objects are compiled at build
time and embedded.

## A worked incident

A service is being killed and nobody knows why. `journalctl` shows it starting,
then nothing.

**1. Watch for it.** In `/etc/wake/wake.toml`:

```toml
[[triggers.watched_process]]
name      = "mstr-death"
comm_glob = "mstr*"
exit_code = "any-nonzero"
cooldown  = "5m"

[triggers.oom]
enabled  = true
cooldown = "1m"
```

```bash
sudo wake verify-config /etc/wake/wake.toml && sudo systemctl restart wake
```

**2. Wait.** Wake writes nothing until the service dies. `wake status` shows
the ring filling and, importantly, whether anything is being dropped:

```
wake v0.1.0 (pid 8821), recording for 4h12m

Drops:      none — every event the kernel produced is accounted for

Ring:       184203/200000 events, 71.4 MiB/128.0 MiB, window 5m0s
            covering 4m58s (2026-08-02T14:15:09Z to 2026-08-02T14:20:07Z)
Classes:    exec, exit, signal, oom, open, connect

Triggers:
  mstr-death           process  cooldown 5m0s
  oom                  oom      cooldown 1m0s

Snapshots:  0 on disk, 0 B
```

**3. It dies.** Wake freezes the ring and writes a snapshot. The freeze is
O(1); recording continues into a fresh ring while the frozen one is serialised,
so the aftermath is captured too.

```
$ sudo wake snapshots list
20260802-142007-process-mstr    4.2 MiB  184203 events  process: mstr was killed by SIGKILL
```

**4. Read it.**

```bash
$ sudo wake snapshots show 20260802-142007-process-mstr | jq .trigger
$ sudo zstdcat /var/lib/wake/snapshots/20260802-*/events.jsonl.zst \
    | jq -c 'select(.class=="open" and .errno!=null)' | tail -20
{"ts":"2026-08-02T14:20:06.881Z","class":"open","pid":4321,"comm":"mstr",
 "path":"/var/opt/mstr/cache/cube_4471.cub","flags":"O_RDWR","ret":-28,"errno":"ENOSPC"}
```

The disk filled, the cube write failed, and a supervisor killed the service.
None of that was in the application's log.

**5. Take it away.** A snapshot is a directory: copy it off the box and read it
anywhere. The format is a versioned public contract, documented in
`docs/snapshot-format.md` to a standard that a consumer can be written from the
document alone, without reading this repository's source. A reference fixture
snapshot ships in `testdata/fixtures/` so a consumer's tests have something
stable to read without needing a live daemon, root, or a kernel.

Drop counters travel with the snapshot in its manifest, so a downstream tool can
tell an incomplete capture from a complete one rather than reasoning over a gap
it cannot see.

## Guarantees

These are requirements, not aspirations, and each has a test.

- **Nothing disappears silently.** Every buffer boundary has a drop counter,
  and every counter appears in `wake status` and in every snapshot manifest.
  A flight recorder that loses events quietly is worse than none.
- **Decode is total.** A record Wake does not understand is kept as a generic
  event with its raw payload, never discarded.
- **No file contents, ever.** Paths, flags and errnos only. This is a hard
  privacy line, not a deferral.
- **Redaction happens before serialisation**, in fact before the ring, so a
  masked value cannot leak through a watch stream either.
- **Snapshots are 0700.** They contain other people's command lines.
- **Tracepoint layouts are verified against the running kernel** and the
  provenance is cited in the source. No field offsets from memory.

## Overhead

The budget is < 1% CPU and < 128 MiB RSS at 10k events/s sustained. The
in-repo load generator makes this measurable:

```bash
make perf   # runs the generator, records results in docs/perf.md
```

## Development

```bash
make test         # unprivileged unit tests, -race. Never needs a kernel.
make integration  # kernel-dependent tests, needs root
make lint
```

Unit tests use an injected fake event source; only `make integration` touches
the kernel. `SPEC.md` is the authoritative specification and `CLAUDE.md` is the
guidance for agents working in this repository.

## Licence

Apache-2.0.
