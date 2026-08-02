# 0008. Snapshot-on-shutdown is opt-in

## Status

Accepted. Resolves SPEC.md §9 open question 6.

## Context

Open question 6 asked whether stopping the daemon should imply a trigger,
leaning towards an opt-in config flag.

## Decision

Opt-in, via `snapshot_on_shutdown = false` in `wake.toml` (default false).

Default-on would mean every `systemctl restart wake`, every package upgrade,
and every configuration reload produces a snapshot. Snapshots are the thing
retention has to prune; filling the retention budget with the record of Wake's
own restarts would evict the snapshot of the incident someone actually cares
about. That is a failure mode worth designing out rather than documenting.

Where it is genuinely wanted — a host being drained deliberately, a debugging
session where the operator wants the tail of the ring on the way out — the flag
turns it on, and the resulting snapshot's trigger type is `manual` with the
reason "daemon shutting down", so it is distinguishable in the manifest.

## Consequences

- The default install produces snapshots only for real triggers.
- Operators who want the shutdown tail must know the flag exists; the example
  config documents it, and the example config is parsed by a test, so it cannot
  silently rot.
