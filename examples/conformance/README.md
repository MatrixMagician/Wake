# Example: a conforming snapshot reader

`conformance.py` reads Wake snapshots and reports on each of the four consumer
obligations from `docs/snapshot-format.md` §6.

It exists for two reasons.

**It is evidence.** SPEC.md §6.2 claims the format is implementable "from the
documentation alone, without reading Wake's source". That is an easy claim to
make and an easy one to be wrong about. This reader was written against the
document and the reference fixture only, in a language Wake is not written in,
which is the only way to test the claim rather than assert it. Writing it found
one genuine gap in the documentation — the timestamp-parsing traps now recorded
in §6.5.

**It is a worked example of "conforming".** The obligations are short to state
and easy to skim past. Seeing what §6.3 actually looks like in output:

```
[§6.3] INCOMPLETE: 4346 event(s) lost before capture
       (userspace_ring.exec=3, userspace_ring.exit=20, userspace_ring.open=4323).
       Any conclusion drawn from this timeline must allow for the gap.
```

...makes the point better than the prose does. That snapshot was real, taken on
a developer machine at default settings. A consumer that stayed quiet about it
would have presented 1,500 events as the whole story when 4,346 more had been
dropped.

## Running it

```bash
python3 conformance.py ../../testdata/fixtures/reference-snapshot
python3 conformance.py /var/lib/wake/snapshots          # a whole root
```

Exit status is 0 if every snapshot read cleanly. Needs Python 3.11+ and either
the `zstandard` module or the `zstdcat` binary.

## What it checks

| Obligation | Behaviour |
|---|---|
| §6.1 | Refuses a `schema_version` it was not written for, rather than guessing |
| §6.2 | Skips directories beginning with `.` — writes in progress |
| §6.3 | Reports non-zero drop counters as an explicit incompleteness warning |
| §6.4 | Tolerates unknown classes, fields and drop boundaries; retains `generic` events |
| §3 | Verifies the oldest-first ordering guarantee, parsing timestamps rather than comparing strings |
| §3.4 | Verifies that a negative `ret` always carries an `errno` |

## Status

**This is an example, not a supported tool.** It is exercised by
`internal/snapshot/example_test.go` so it cannot silently rot, but it has no
compatibility promise of its own. Copy it and adapt it; do not depend on it.
