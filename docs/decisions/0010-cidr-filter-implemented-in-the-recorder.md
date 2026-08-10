# 0010. The CIDR filter lives in the recorder, and excludes rather than drops

## Status

Accepted. Supersedes the consequences of
[0002](./0002-cidr-filtering-in-userspace.md) that named `loader.Options`.

## Context

0002 decided that CIDR filtering happens in userspace rather than in kernel,
and recorded as a consequence that "`loader.Options.CIDRs` is documented as
userspace-applied, so that nobody reading the field assumes an in-kernel
guarantee that is not there."

That consequence described something that had never been built. `filters.cidrs`
was parsed, validated, and carried into `loader.Options.CIDRs` — and then read
by nothing at all. No code filtered by destination address anywhere, in kernel
or out. An operator who set the key got no filtering and no warning, while an
accepted decision record stated the filter existed.

Implementing it raised two questions 0002 had not needed to answer, plus one
about where the field belongs now that something reads it.

## Decisions

### 1. The filter runs in the recorder, not the loader

Between decode and the ring, so an excluded event reaches neither the ring, the
watch fan-out, nor the trigger engine — exactly the position 0002 specified
("immediately after decode and before the ring").

The prefixes moved with it: `loader.Options.CIDRs` is gone and
`recorder.Options.CIDRs` replaces it. A CIDR field on the kernel-facing struct
is precisely what invites the in-kernel assumption 0002 exists to deny, and
`internal/loader` never read it. This supersedes 0002's consequence bullet.

### 2. An excluded event is not a drop

It is counted at no boundary. A *Drop* means something that existed was lost;
an event the operator configured Wake not to record was never wanted. The
in-kernel cgroup, comm, path and port filters behave the same way — they simply
never emit — so counting this one would make a correctly-configured recorder
look lossy for obeying its configuration.

This required amending CONTEXT.md, whose *Scope* entry listed CIDR sets as
in-kernel and declared that "anything filtered in userspace is a bug, not a
scope" — written before 0002 moved CIDR out of the kernel, and never updated to
match. CONTEXT.md now names this filter separately from Scope, so that "scope"
keeps meaning "in kernel", and states that neither Scope nor this filter
produces a Drop. The Go identifier is `destinationAllowed`, deliberately not
`inScope`.

### 3. An unclassifiable destination is kept

A connect event whose destination address the decoder could not render — an
address family it does not recognise, yielding an empty `daddr` — passes the
filter. Discarding evidence because it could not be classified is how a record
quietly becomes incomplete, which is the failure this project exists to prevent.

## Consequences

- `filters.cidrs` now does what SPEC.md §2 goal 2 and 0002 both said it did.
  The remaining deferral is only the in-kernel LPM-trie form, per 0002's own
  closing note; `docs/milestones.md` says so explicitly.
- Prefixes are masked on parse, so a value written with host bits set
  ("10.0.0.1/8") means the network the operator intended. This is
  belt-and-braces — `netip.Prefix.Contains` already ignores host bits — but it
  keeps the parsed value canonical wherever it is echoed back.
- A v4-mapped IPv6 destination is matched against v4 prefixes, because the
  decoder unmaps before this filter sees the address.
- CONTEXT.md gained a *Network filter* entry. It is a glossary, not an ADR, so
  it is corrected in place rather than superseded; this record is the reason.
