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

### Fixed

- `proc/fd_listing.txt` no longer renders unreadable fd targets as a blank
  string. A failed `readlink()` is now one of the bracketed sentinels
  `[closed]`, `[permission denied: needs CAP_SYS_PTRACE]` or `[unreadable]`,
  documented in `docs/snapshot-format.md` §5.1. This does **not** bump
  `schema_version`: the field's type and meaning are unchanged, and a consumer
  that displays targets verbatim is unaffected. A consumer that resolves
  targets as paths already had to cope with a blank value and must now skip
  bracketed ones.
- The shipped systemd unit now grants `CAP_SYS_PTRACE`. Without it every fd
  target in every snapshot was silently blank, because `readlink()` on
  `/proc/<pid>/fd/<fd>` is gated on `PTRACE_MODE_READ` rather than on file
  permissions. Found by running the unit, not by reading it.
- The unit no longer declares `ExecReload=/bin/kill -HUP $MAINPID`, which
  **stopped the recorder**: Wake did not handle `SIGHUP`, so the default
  disposition terminated it while systemd reported a successful reload. Wake
  does not reconfigure in place, so `systemctl reload` now correctly fails as
  not applicable. `SIGHUP` is additionally caught and ignored with a warning so
  that an inherited hangup from any source cannot stop a recording.

### Added

- `wake doctor` check for the `CAP_SYS_PTRACE` fd-listing gate, reporting the
  denial and its remedy rather than leaving it to be discovered in a snapshot.
- `internal/cli/unitfile_test.go` pins the shipped unit's capability set and the
  absence of `ExecReload=`, since nothing else type-checks a `.service` file.

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
