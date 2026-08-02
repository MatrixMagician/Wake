# AGENTS.md

Wake is an eBPF incident flight recorder (single Go binary, Linux, snapshots on trigger).

**The full agent guidance lives in [`CLAUDE.md`](./CLAUDE.md).** It is the single source of
truth for commands, architecture, invariants, and conventions; this file exists so agents
that look for `AGENTS.md` find their way there. Edit `CLAUDE.md`, not this file.

Non-negotiables, repeated here because they are cheap to state and expensive to violate:

1. `SPEC.md` is authoritative — read the relevant section before implementing.
2. Never capture file contents. Redact before serialisation. Snapshots are 0700.
3. Every dropped event is counted and surfaced in `status` and every snapshot manifest.
4. Verify tracepoint layouts against the running kernel and cite the source in a comment.
5. Unit tests run unprivileged; kernel tests are build-tagged `integration`.
6. British English in docs and user-facing strings.

Quick start: `make build && make test`, then `sudo ./wake doctor`.
See `docs/agents/` for issue tracker, triage labels, and domain doc conventions.
