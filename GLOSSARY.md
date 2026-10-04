# CONTEXT — Wake's ubiquitous language

Definitions are binding: these words mean exactly this in code, docs, config, and issues.

**Event** — one observed kernel occurrence in a known *class*: `exec`, `exit`, `signal`,
`oom`, `open`, `connect`. Produced in kernel, decoded in userspace, serialised as one JSONL
line. An event that cannot be decoded into a known class becomes a *generic record* with its
raw payload retained; it is never discarded.

**Class** — an independently enable/disable-able family of events, with its own BPF program,
decode path, filters, and drop counter.

**Scope** — the in-kernel filter set deciding what is recorded at all: cgroup subtree, comm
allow/deny list, path prefixes, port/CIDR sets. Scope is enforced *before* an event crosses
to userspace; anything filtered in userspace is a bug, not a scope.

**Ring** — the bounded in-memory buffer of decoded events. Bounded simultaneously by time
window, event count, and memory budget; whichever binds first wins. Oldest is overwritten.
The ring is the only steady-state memory consumer.

**Drop** — an event that existed but is not in the ring, at any boundary (BPF ringbuf full,
userspace ring overwrite, watch fan-out backpressure). Every drop is counted per class per
boundary and reported in `status` and every snapshot manifest. Drops are honest, never hidden.

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
