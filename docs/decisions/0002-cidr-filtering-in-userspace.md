# 0002. CIDR filtering happens in userspace, not in kernel

## Status

Accepted.

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

## Amendment: where the filter actually lives

The decision above is unchanged — CIDR filtering is in userspace — but this
record described a consequence that had never been built. `filters.cidrs` was
parsed and validated, carried into `loader.Options.CIDRs`, and then read by
nothing at all: no code filtered by address, in kernel or out. An operator who
set the key got no filtering and no warning.

Implemented as specified: the filter now runs in `internal/recorder`,
immediately after decode and before the ring, so a connect event outside every
configured prefix reaches neither the ring, the watch fan-out, nor the trigger
engine.

The field moved with it. `loader.Options.CIDRs` is gone, and the prefixes are
now `recorder.Options.CIDRs`, because a CIDR field on the kernel-facing struct
is exactly what invites a reader to assume the in-kernel guarantee this record
says does not exist. The original consequence bullet naming `loader.Options`
stands as written history; this paragraph supersedes it.

Two behaviours were settled during implementation that the original record did
not state:

- A filtered event is **out of scope, not a drop**, and is counted at no
  boundary. Drop counters mean something that should have been kept was lost;
  an event the operator configured away was never wanted. This matches the
  in-kernel cgroup, comm, path and port filters, which simply never emit.
- A connect event whose destination address the decoder could not render — an
  address family it does not recognise, yielding an empty `daddr` — is
  **kept**. Discarding evidence because it could not be classified is how a
  record quietly becomes incomplete.
