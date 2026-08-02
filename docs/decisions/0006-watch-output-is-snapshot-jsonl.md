# 0006. `wake watch` emits the same JSONL as a snapshot

## Status

Accepted. Resolves SPEC.md §9 open question 4.

## Context

Open question 4 asked whether `wake watch` output should be the same JSONL as
snapshots, leaning yes ("one decoder path").

## Decision

Yes, and more strongly than the question implies: there is one serialisation
function, `event.Event.MarshalJSONLine`, used by both the snapshot writer and
the control socket's watch stream.

Redaction is applied in the recorder, on the way into the ring, rather than at
snapshot time. That is what makes the guarantee hold: a secret that never
enters the ring cannot leak through a watch stream either, and there is only
one code path that could be got wrong.

The watch stream wraps each event in a `{"event": {...}}` envelope, because the
control protocol also carries errors and status. `wake watch` unwraps it, so
what reaches a terminal or a pipe is byte-identical to a snapshot line.

## Consequences

- A tuning session with `wake watch | jq` and an analysis of
  `events.jsonl.zst | jq` use identical filters. This is the whole point.
- A Sift adapter written against `docs/snapshot-format.md` can also consume a
  live watch stream without a second parser.
- Changing the event schema changes both surfaces at once, which is correct:
  they are the same contract.
