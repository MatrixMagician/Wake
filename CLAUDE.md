# CLAUDE.md

Guidance for coding agents (Claude Code, jcode, Codex) working in this repository.
`AGENTS.md` is a pointer to this file — keep the two in sync by editing this one.

## Project

Wake is a single-binary **eBPF incident flight recorder** for Linux. It attaches BPF
programs to stable kernel tracepoints, streams process/file/network/signal/OOM events
into a **bounded in-memory ring**, writes nothing in steady state, and persists a
self-contained **snapshot** of the last N minutes only when a trigger fires.

**SPEC.md is the authoritative specification.** Read the relevant section before
implementing anything. Milestones and their acceptance criteria are SPEC.md §6; the
repository layout is §7. Snapshots are a versioned public contract consumed by the
sibling project **Sift** (`../Sift`) — changing the schema is a breaking change.

## Commands

Go ≥ 1.23, BPF C compiled at build time with clang (bpf2go/CO-RE), objects embedded.

```bash
make build              # go generate (bpf2go) + go build ./cmd/wake
make test               # unit tests, unprivileged, -race
make integration        # //go:build integration, requires root + live kernel
make lint               # go vet + golangci-lint
make perf               # load generator + overhead measurement -> docs/perf.md
sudo ./wake doctor      # BTF / tracepoints / caps / ringbuf preflight
```

"Done" for a milestone = `make lint test` clean, its integration tests pass as root,
and the acceptance bullets in SPEC.md §6 are demonstrably met. Do not start M(n+1)
while M(n) is red.

## Architecture

```
BPF (tracepoints + in-kernel filters) --ringbuf--> reader -> decode -> bounded ring
                                                       |-> enrichment cache (LRU)
                                                       |-> trigger engine (sd-bus, socket, signal)
                                                       `-> snapshot writer
```

- `bpf/` — BPF C, one file per event class plus shared maps/filters. Keep it minimal
  and boring: filtering and truncation in kernel, everything else in Go.
- `internal/loader` — cilium/ebpf plumbing and bpf2go output.
- `internal/decode` — wire layouts → typed events. **Decode is total.**
- `internal/ring` — bounded by time *and* count *and* memory, whichever binds first.
- `internal/enrich` — pid → comm/ppid-chain/cgroup/unit/container/uid, size-capped LRU,
  maintained from exec/exit so already-dead processes stay attributable.
- `internal/trigger` — watched-process, OOM, signal, manual, systemd-unit-failed; per-rule cooldown.
- `internal/snapshot` — manifest.json + events.jsonl.zst + system.json + proc/ scrape.
- `internal/ctl` — root-owned unix socket for `status`/`trigger`/`watch`.
- `internal/config` — the single TOML file at `/etc/wake/wake.toml`.

## Load-bearing invariants

- **Nothing disappears silently.** Every buffer boundary (BPF ringbuf, userspace ring,
  watch fan-out) has a drop counter; counters appear in `wake status` and in *every*
  snapshot manifest. A flight recorder that loses events quietly is worse than none.
- **Decode is total.** Unknown or extended event layouts decode to a generic record with
  the raw payload retained — never dropped, never panicked on.
- **Privacy lines are hard requirements, not polish.** No file contents, ever. Redaction
  of argv/paths happens *before* serialisation. Snapshots are 0700.
- **Freezing is cheap.** A trigger atomically swaps the active ring for a fresh one;
  the frozen ring serialises off the hot path so recording continues during snapshot writing.
- **The ring is the only steady-state memory consumer.** Everything else is O(1) or capped.
- **Verify tracepoint layouts against the running kernel** (`/sys/kernel/tracing/events/<sub>/<ev>/format`,
  BTF) before writing decode code, and cite what was consulted in a provenance comment.
  Never code tracepoint fields from memory.
- **Tracepoints over kprobes.** Any kprobe requires a decision record saying why the
  tracepoint was insufficient.
- **Unit tests never need privileges** — the event source is injectable; kernel-dependent
  tests are build-tagged `integration`.

## Conventions

- Prefer boring technology: stdlib, `cilium/ebpf`, `klauspost/compress/zstd`, `godbus/dbus`,
  `BurntSushi/toml`, `spf13/cobra`. Justify anything beyond these.
- Errors wrap with context (`fmt.Errorf("...: %w", err)`); no panics outside `main` init paths.
- British English in docs and user-facing strings.
- Config precedence: CLI flags > `WAKE_*` env > `/etc/wake/wake.toml` > defaults.
  The `[classes]` table *merges* with the defaults rather than replacing them, so
  omitting a class leaves it enabled; disabling one requires saying `false`.
- Record decisions for SPEC.md §9 open questions in `docs/decisions/NNNN-title.md`.
- Licence: Apache-2.0. Commit per logical change, imperative subject line.

## Working with jcode

- Small, independent lookups belong in one parallel tool block; sequence only real dependencies.
- Use the `todo` tool for anything multi-step, and keep it current.
- Use `swarm` for genuinely parallel workstreams (e.g. separate `internal/` packages behind
  agreed interfaces). Routing: planning/review → `claude-opus-5` (high effort); implementation
  and tests → `claude-sonnet-5` (high). Always pass a `label`. Only the root session spawns.
- Prefer fixing over reporting. Validate with `make lint test` before claiming done.

## Agent skills

This repo is configured for the engineering skills (`triage`, `to-spec`, `to-tickets`,
`implement`, `tdd`, `wayfinder`, `code-review`, `diagnosing-bugs`, `domain-modeling`).

- **Issue tracker:** see `docs/agents/issue-tracker.md`.
- **Triage labels:** see `docs/agents/triage-labels.md`.
- **Domain docs:** see `docs/agents/domain.md` — single-context: root `CONTEXT.md`
  plus ADRs in `docs/decisions/`.

Read the relevant `docs/agents/` file before using a skill that touches issues or docs.
