# Domain docs

**Layout: single-context.** This is one Go binary with one bounded context.

- `CONTEXT.md` (repo root) — the ubiquitous language: what an *event*, *ring*, *trigger*,
  *snapshot*, *scope*, and *enrichment* mean here. Read it before naming anything new.
- `docs/decisions/NNNN-title.md` — architecture decision records. SPEC.md §9 lists the
  open questions that must end up here; any kprobe use requires one (SPEC.md §8).

Consumer rules:
- Before implementing, read `SPEC.md` (authoritative) then `CONTEXT.md` (vocabulary).
- When a decision is made that a future reader would otherwise have to re-derive from the
  kernel — tracepoint choice, field layout surprise, sandboxing option loosened — write an ADR.
- ADRs are append-only: supersede with a new record, do not rewrite history.
- Keep `CONTEXT.md` terminology and the Go identifiers in agreement. If they drift, the
  code is renamed to match the domain, not the other way round.

ADR format: `# NNNN. Title` / `## Status` / `## Context` / `## Decision` / `## Consequences`.
