# Wake — eBPF Incident Flight Recorder

**Specification v0.1 — for implementation via Claude Code / agentic harness**

---

## 1. Overview

Wake is a single-binary flight recorder for Linux hosts. It loads a small set of eBPF programs onto stable kernel tracepoints, streams process-lifecycle, file-access, network, signal, and OOM events into a **bounded in-memory ring buffer**, and writes nothing during normal operation. When a **trigger** fires — a watched process exits abnormally, an OOM kill occurs, a signal of interest is delivered, or an operator asks — Wake freezes the ring, enriches it with process/cgroup/container/unit attribution, and persists a self-contained **snapshot**: the last N minutes of kernel-level truth surrounding the incident.

Wake is a diagnostic tool for support and reliability engineers, not a security platform. It answers "what actually happened in the ninety seconds before this thing died?" — the question logs cannot answer because applications only log what they chose to.

Reference platform: Fedora (kernel ≥ 6.x with BTF, which Fedora ships), rootless-unfriendly by nature (see privileges, §3), systemd service deployment. Snapshots are designed to be consumed by downstream triage tooling; the snapshot schema is a versioned public contract.

### Positioning vs prior art
- **auditd:** capture-everything-to-disk with painful rules; Wake records to memory only and persists only on trigger.
- **Tetragon / Tracee / Falco:** security observability platforms — policy engines, enforcement, fleet scale. Wake is deliberately one binary, one host, one job.
- **strace/ltrace:** require foresight and impose brutal overhead; Wake is always-on at ~negligible cost.
- **sosreport/supportconfig:** state *after* the fact; Wake preserves the *events leading up to* the fact.

---

## 2. Goals and Non-Goals

### Goals
1. **Event classes (v1):** process exec (with argv, truncated), process exit (code/signal), signal delivery (configurable signal set), OOM kill, file open attempts (success *and* failure, with flags and errno), TCP connect attempts (v4/v6, with result). Each class independently enable/disable-able.
2. **In-kernel filtering:** scope by cgroup subtree, comm allow/deny list, path prefixes for file events, and port/CIDR sets for network events — applied in BPF before events cross to userspace.
3. **Bounded ring:** retain by time window *and* event count *and* memory budget, whichever binds first; overwrite oldest; per-class drop counters surfaced honestly in status and in every snapshot.
4. **Trigger engine:** (a) watched-process rules (comm/cgroup/unit glob + exit-code predicate), (b) OOM kill anywhere in scope, (c) configured signal delivered to scoped process, (d) manual (`wake trigger`, SIGUSR1, unix socket), (e) systemd unit entering failed state (via sd-bus subscription). Cooldown per rule to prevent snapshot storms.
5. **Snapshot:** directory containing `manifest.json` (trigger, host, wake version, schema version, drop stats, config hash), `events.jsonl.zst`, `system.json` (uname, meminfo/pressure at trigger, uptime), and `proc/` scrape of the triggering process where it still exists (status, limits, fdinfo list, cgroup — never file *contents*).
6. **Enrichment:** PID → comm, ppid chain (depth-limited), cgroup path → systemd unit / container ID (Podman and Kubernetes cgroup layouts), UID → name; performed at snapshot time from a continuously-maintained lightweight cache, so short-lived processes that already exited are still attributable.
7. **Snapshot contract:** schema documented such that a consumer is implementable from the documentation alone, without reading Wake's source; a reference fixture snapshot ships in-repo so a consumer's tests have something stable to read.
8. Single static Go binary; BPF objects compiled at build time (bpf2go/CO-RE) and embedded — no clang, headers, or kernel modules on the target.

### Non-Goals (v1)
- No security policy, detection rules, enforcement, or alerting pipelines.
- No packet capture or payload inspection; network events are connection metadata only.
- No file-content capture, ever — paths, flags, and errnos only. This is a hard privacy line, not a deferral.
- No fleet mode, no central server, no TLS shipping; a snapshot is a directory you copy.
- No support for kernels without BTF (no fallback compilation path); minimum kernel documented in M1 after verifying which tracepoints/helpers bind on the oldest target.
- No Windows/macOS.

---

## 3. Constraints and Reference Environment

| Constraint | Value |
|---|---|
| Language | Go ≥ 1.23; `github.com/cilium/ebpf` + bpf2go; BPF C compiled at build time with clang, embedded via go:embed |
| Kernel interface | Prefer stable tracepoints: `sched:sched_process_exec`, `sched:sched_process_exit`, `signal:signal_deliver`, `oom:mark_victim`, `syscalls:sys_exit_openat*`; network via `inet_sock_set_state` tracepoint, with a kprobe fallback only if the tracepoint proves insufficient (decision recorded in `docs/decisions/`) |
| Transport | BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`), not perf buffers; per-CPU accounting for drops |
| Privileges | Root, or `CAP_BPF + CAP_PERFMON + CAP_SYS_RESOURCE` (+ `CAP_DAC_READ_SEARCH` for /proc scrapes); ship a hardened systemd unit (ProtectSystem=strict, ReadWritePaths=snapshot dir, NoNewPrivileges) |
| Overhead budget | < 1% CPU and < 128 MiB RSS at 10k events/s sustained on the reference box; a load-generator script in-repo makes this measurable, and M-gates enforce it |
| Snapshot dir | `/var/lib/wake/snapshots/<timestamp>-<trigger>/`, 0700, retention by count and total size |
| Licence | Apache-2.0 |

---

## 4. Architecture

```
        kernel space                          userspace (single Go process)
┌──────────────────────────────┐   ringbuf   ┌─────────────────────────────────┐
│ BPF progs on tracepoints     │────────────▶│ reader → decode → ring (bounded)│
│  exec/exit/signal/oom/       │             │            │                    │
│  openat/inet_sock_set_state  │             │      enrichment cache           │
│ in-kernel filters:           │             │  (pid→comm/cgroup/unit/ctr,     │
│  cgroup scope, comm, path,   │             │   maintained from exec/exit)    │
│  port/CIDR maps              │             │            │                    │
└──────────────────────────────┘             │      trigger engine ◀── sd-bus, │
                                             │            │        socket, sig │
                                             │      snapshot writer            │
                                             │   manifest + events.jsonl.zst   │
                                             │   + system.json + proc/         │
                                             └─────────────────────────────────┘
```

Design rules:
- **Decode is total:** unknown/extended event layouts decode to a generic record with raw payload retained, never dropped silently — nothing disappears without being counted.
- **The ring is the only steady-state memory consumer:** enrichment cache is size-capped LRU; everything else is O(1).
- **Freezing is cheap:** trigger swaps the active ring for a fresh one atomically; the frozen ring is serialised off the hot path, so recording continues through snapshot writing.
- **Config is one TOML file** (`/etc/wake/wake.toml`): scopes, event classes, filters, triggers, ring bounds, retention, redaction (argv/path regex masking — support engineers capture other people's boxes; redaction is config, not code).

### Event schema (JSONL, indicative)

```json
{"ts":"2026-08-02T14:20:07.123456789Z","class":"exec","pid":4321,"ppid":4300,
 "comm":"smtpd","argv":["smtpd","-d"],"cgroup":"/system.slice/mstr.service",
 "unit":"mstr.service","container":null,"uid":987}
{"ts":"…","class":"open","pid":4321,"comm":"smtpd","path":"/etc/ssl/certs/…",
 "flags":"O_RDONLY","ret":-13,"errno":"EACCES", …}
{"ts":"…","class":"connect","pid":4321,"daddr":"10.0.4.7","dport":587,
 "proto":"tcp","state":"SYN_SENT→CLOSE","ret":-110,"errno":"ETIMEDOUT", …}
```

Every event carries the enrichment triple (cgroup/unit/container) resolved at snapshot time; `schema_version` lives in the manifest and governs the whole file.

---

## 5. CLI Design

```
wake run [--config /etc/wake/wake.toml]     # the daemon (systemd-notify aware)
wake status                                  # ring occupancy, drops, uptime, active triggers
wake trigger [--reason "text"]               # manual snapshot
wake watch [--class exec,oom] [--unit U]     # live decoded tail (debugging/tuning aid)
wake snapshots [list|show <id>|prune]
wake doctor                                  # BTF present? tracepoints bindable? caps held?
                                             # ringbuf supported? SELinux/systemd sandbox hints
wake verify-config <file>                    # parse + semantic checks, exit-code gated
```

`status`, `trigger`, and `watch` talk to the daemon over a root-owned unix socket; `watch` is explicitly a tuning aid and rate-limits itself rather than competing with the recorder.

---

## 6. Milestones and Acceptance Criteria

Each milestone lands with tests, `go vet`, `golangci-lint`, and `-race` clean. BPF-dependent integration tests are build-tagged (`//go:build integration`) and run as root against the live kernel in a documented `make integration` path; unit tests use an injected fake event source and never require privileges.

**M1 — Skeleton + exec/exit pipeline end-to-end**
✔ bpf2go build embeds objects; daemon loads exec/exit tracepoints, decodes into the ring; `wake watch` shows live events for a test process; `doctor` reports BTF/caps/tracepoint bindability; integration test proves an exec'd fixture binary appears with correct argv (truncation case included); drop counters wired even if zero.

**M2 — Ring semantics + enrichment cache + status**
✔ Ring honours time/count/memory bounds under a load generator (in-repo) with property tests on eviction order; enrichment cache attributes a process that exited 30 s ago to its unit/container in a snapshot; Podman and raw-systemd cgroup layouts fixture-tested; `status` complete.

**M3 — Remaining event classes + in-kernel filtering**
✔ signal/oom/openat/connect classes implemented against verified tracepoint layouts (provenance comments citing the running kernel's format files/BTF); cgroup-scope, comm, path-prefix, and port filters demonstrably drop events *in kernel* (verified via BPF-side counters, not userspace inference); overhead budget met at 10k events/s with filters active — measured, recorded in `docs/perf.md`, and enforced as a CI-adjacent script.

**M4 — Trigger engine + snapshot writer**
✔ All five trigger types fire in integration tests (including sd-bus unit-failure via a purposely-failing test unit); trigger→snapshot completes with recording uninterrupted (events generated during writing appear in the *next* ring); snapshot contains manifest, zstd JSONL, system.json, proc/ scrape; cooldown prevents storming; a snapshot taken mid-load includes accurate drop stats.

**M5 — Redaction + retention + snapshot contract**
✔ Argv/path redaction masks configured patterns before serialisation (test proves masked values never reach disk); retention pruning by count and size; snapshot schema documented in `docs/snapshot-format.md` to the standard that a consumer can be written from the doc alone; reference fixture snapshot committed and validated by a schema test.

**M6 — Hardening + packaging + release**
✔ Hardened systemd unit ships and daemon runs under it (integration-verified — sandboxing options and BPF interact non-obviously; document what had to be loosened and why); `doctor` detects and explains the known failure modes (missing caps, locked-down `kernel.unprivileged_bpf_disabled` irrelevance under caps, SELinux denials hint); goreleaser static binaries; README with a worked incident walkthrough: break a service, watch Wake catch it, read the snapshot it produced.

---

## 7. Repository Layout

```
wake/
├── SPEC.md / CLAUDE.md
├── bpf/                    # BPF C sources (one file per event class) + shared maps/filters
├── cmd/wake/main.go
├── internal/
│   ├── loader/             # cilium/ebpf plumbing, bpf2go output
│   ├── decode/
│   ├── ring/
│   ├── enrich/
│   ├── trigger/
│   ├── snapshot/
│   ├── ctl/                # unix-socket protocol (status/trigger/watch)
│   └── config/
├── deploy/wake.service     # hardened unit
├── testdata/               # fixture snapshots, cgroup layouts, load generator
├── docs/{snapshot-format.md, perf.md, decisions/}
└── Makefile                # build (clang), test, integration, perf targets
```

---

## 8. Guidance for the Implementing Agent

- **Verify every tracepoint layout against the running kernel** (`/sys/kernel/tracing/events/…/format` and BTF) before writing decode code; cite what was consulted in a provenance comment. Tracepoint fields are stable-ish, not identical across versions — do not code from folklore or training-data memory.
- Drop accounting is load-bearing: a flight recorder that silently loses events is worse than none. Every buffer boundary (BPF ringbuf, userspace ring, watch fan-out) has a counter, and counters appear in `status` and every manifest.
- The privacy lines are hard requirements: no file contents, redaction before serialisation, 0700 snapshots. When in doubt, capture less.
- Prefer tracepoints over kprobes; any kprobe use requires a decision record explaining why the tracepoint was insufficient.
- Keep the BPF C minimal and boring — filtering and truncation in kernel, everything else in Go. Complexity lives where it can be unit-tested.
- British English in docs and user-facing strings.

## 9. Open Questions (record decisions in `docs/decisions/`)

1. `inet_sock_set_state` tracepoint vs `tcp_connect`/`tcp_v4_connect` kprobes for capturing connect *attempts with errno* — verify what the tracepoint actually yields for failed connects during M3 spike.
2. Whether UDP "connects" (sendto to new destinations) are worth a v1 class or deferred (leaning: defer).
3. Minimum kernel version after M1's binding survey (leaning: whatever current Fedora N-1 ships).
4. Whether `wake watch` output format should be the same JSONL as snapshots (leaning: yes, one decoder path).
5. Kubernetes cgroup attribution depth (pod UID + container ID vs full kubelet parsing) — leaning: parse IDs from cgroup path only, no kubelet API.
6. Snapshot-on-shutdown (daemon stop = implicit trigger?) — leaning: opt-in config flag.
