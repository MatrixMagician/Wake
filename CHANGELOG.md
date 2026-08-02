# Changelog

Wake's releases, and — separately and more importantly — the history of its
**snapshot schema**.

The snapshot schema is a versioned public contract
(`docs/snapshot-format.md`). Consumers are written against a
`schema_version`, so every change to it is recorded here whether or not it
coincides with a release. That is the promise SPEC.md §6.4 makes; this file is
where it is kept.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## Snapshot schema history

| `schema_version` | Since | Change |
|---|---|---|
| 1 | initial | First public contract. Six event classes (`exec`, `exit`, `signal`, `oom`, `open`, `connect`) plus `generic`; four drop boundaries (`kernel_ringbuf`, `decode`, `userspace_ring`, `watch_fanout`); manifest, zstd-compressed JSONL events, `system.json`, and an optional `proc/` scrape. |

### What bumps this number

A change an existing reader could **misinterpret**: a field changing type or
meaning, a field being removed, an ordering guarantee being relaxed, a privacy
boundary moving.

A change that is **additive** — a new optional field, event class, trigger type
or drop boundary — does not. Consumers are required to tolerate those
(`docs/snapshot-format.md` §6.4), which is what makes them safe.

### Before you bump it

Bumping `event.SchemaVersion` breaks every consumer written against the previous
version. That is sometimes correct, but it is never routine. In particular, if a
test tells you a fixture no longer matches the code, the first question is
whether the *code* changed the serialised form — not whether the fixture needs
regenerating.

---

## [Unreleased]

### Added

- Snapshot consumption contract (SPEC.md §6): who the consumer is, what Wake
  ships, four normative consumer obligations, and the compatibility promise.
  Recorded in `docs/decisions/0009-consumption-contract.md`.
- `docs/snapshot-format.md` §6, *Consumer obligations*, collecting requirements
  previously scattered through the document's prose.
- Reference fixture now exercises **all seven event classes** and is regenerable
  with `make fixture` from a committed generator.
- `examples/conformance/` — a worked example consumer written from the format
  document alone, demonstrating the four obligations. Writing it surfaced the
  timestamp-parsing traps now documented in `docs/snapshot-format.md` §6.5.
- This file.

### Changed

- The reference fixture's schema test now reports a serialisation change as a
  breaking change to be versioned and recorded, rather than as a stale fixture
  to be regenerated.
