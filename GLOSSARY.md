# CONTEXT — Wake's ubiquitous language

Definitions are binding: these words mean exactly this in code, docs, config, and issues.

**Event** — one observed kernel occurrence in a known *class*: `exec`, `exit`, `signal`,
`oom`, `open`, `connect`. Produced in kernel, decoded in userspace, serialised as one JSONL
line. An event that cannot be decoded into a known class becomes a *generic record* with its
raw payload retained; it is never discarded.

**Class** — an independently enable/disable-able family of events, with its own BPF program,
decode path, filters, and drop counter.

**Scope** — the in-kernel filter set deciding what is recorded at all: cgroup subtree, comm
allow/deny list, path prefixes, port sets. Scope is enforced *before* an event crosses
to userspace; anything else filtered in userspace is a bug, not a scope.

**Network filter** — the one deliberate exception to Scope: `filters.cidrs` restricts
`connect` events by destination network in *userspace*, after decode and before the ring,
because prefix matching in kernel needs an LPM trie per address family and the connect class
is too low-volume to earn that (`docs/decisions/0002-cidr-filtering-in-userspace.md`). It is
named separately from Scope precisely so that "scope" keeps meaning "in kernel". Like Scope,
and unlike a *Drop*, an event it excludes is not counted anywhere: it was never wanted.

**Ring** — the bounded in-memory buffer of decoded events. Bounded simultaneously by time
window, event count, and memory budget; whichever binds first wins. Oldest is overwritten.
The ring is the only steady-state memory consumer.

**Drop** — an event that existed and was *lost*, at any boundary (BPF ringbuf full,
userspace ring overwrite, watch fan-out backpressure). Every drop is counted per class per
boundary and reported in `status` and every snapshot manifest. Drops are honest, never hidden.
An event excluded by *Scope* or the *Network filter* is not a drop: it was never wanted, and
counting it would make a correctly-configured recorder look lossy.

**Trigger** — a rule that causes a snapshot: watched-process exit predicate, OOM kill in
scope, configured signal delivered in scope, manual request, or a systemd unit entering
failed state. Each rule has a cooldown to prevent snapshot storms.

**Freeze** — the atomic swap of the active ring for a fresh one at trigger time. Recording
continues into the new ring while the frozen one is serialised off the hot path.

**Snapshot** — a self-contained directory under `/var/lib/wake/snapshots/<timestamp>-<trigger>/`,
mode 0700, containing `manifest.json`, `events.jsonl.zst`, `system.json`, and a `proc/`
scrape of the triggering process. Its schema is a **versioned public contract**
read by downstream tooling; `schema_version` lives in the manifest and governs
the whole snapshot.

**Enrichment** — the attribution triple (cgroup path, systemd unit, container ID) plus comm,
ppid chain, and user name attached to an event at snapshot time from the enrichment cache.

**Enrichment cache** — a size-capped LRU maintained continuously from exec/exit events, so a
process that has already exited remains attributable.

**Redaction** — configured regex masking of argv and paths applied *before* serialisation.
Redaction is config, not code, because engineers capture other people's machines.

**Doctor** — the preflight command that answers "will Wake work on this host, and if not,
precisely why": BTF present, tracepoints bindable, capabilities held, ringbuf supported,
sandboxing/SELinux hints.
