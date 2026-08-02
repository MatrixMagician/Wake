# 0004. UDP "connects" are deferred beyond v1

## Status

Accepted. Resolves SPEC.md §10 open question 2.

## Context

Open question 2 asked whether UDP destination changes (a `sendto` to a new
destination, or a `connect` on a UDP socket) deserve a v1 event class. The
SPEC leaned towards deferring.

## Decision

Defer. v1 records TCP only.

UDP has no connection state, so there is no equivalent of the SYN_SENT
transition to key on: the only faithful capture is per-datagram, which is a
volume problem rather than a diagnostic one. The incidents Wake is built for —
a service that could not reach its database, an LDAP bind that timed out — are
overwhelmingly TCP. DNS is the obvious UDP counter-example, and DNS failures
are visible in the resulting TCP failure or in the application's own logs.

## Consequences

- `wake.toml` has no UDP knobs, and adding them later is additive.
- A user chasing a DNS-specific incident gets no direct evidence from Wake.
  This is stated plainly in the README rather than left to be discovered.
