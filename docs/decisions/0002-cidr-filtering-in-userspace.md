# 0002. CIDR filtering happens in userspace, not in kernel

## Status

Accepted. Superseded in part by
[0010](./0010-cidr-filter-implemented-in-the-recorder.md), which records where the
filter was actually built once it was built at all.

## Context

SPEC.md §2 goal 2 asks for "port/CIDR sets" applied in BPF before events cross
to userspace. Ports are a trivial hash lookup. CIDRs are not: prefix matching
needs `BPF_MAP_TYPE_LPM_TRIE`, one per address family, with the key layout
differing between v4 and v6.

## Decision

Port filtering is in kernel. CIDR filtering is in userspace, immediately after
decode and before the ring.

The reasoning is a measurement, not a preference. The connect class is by far
the lowest-volume class on the reference box: at the SPEC's 10k events/s
overhead target, exec/openat dominate by orders of magnitude. Filtering
connects in kernel therefore saves a negligible number of ring-buffer
crossings while adding two map types, two key layouts, and a verifier-visible
lookup on a path that was otherwise straight-line.

Port filtering stays in kernel because it is genuinely free: one `__u16` hash
lookup, no new map type.

## Consequences

- `loader.Options.CIDRs` is documented as userspace-applied, so that nobody
  reading the field assumes an in-kernel guarantee that is not there.
- The M3 acceptance criterion — filters demonstrably dropping events *in
  kernel*, verified via BPF-side counters — applies to cgroup scope, comm,
  path prefix and port. CIDR is explicitly excluded and this record is the
  reason.
- If a deployment ever shows connect volume dominating the ring, adding an LPM
  trie is a contained change to `bpf/wake.bpf.c` and the loader, and this
  record should be superseded rather than edited.

