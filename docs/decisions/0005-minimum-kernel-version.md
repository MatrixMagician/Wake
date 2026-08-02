# 0005. Minimum supported kernel is 5.8, with 6.x as the tested floor

## Status

Accepted. Resolves SPEC.md §9 open question 3.

## Context

Open question 3 asked for a minimum kernel version after M1's binding survey,
leaning towards "whatever current Fedora N-1 ships".

The survey (`internal/loader` integration tests, run against
7.1.5-201.fc44.x86_64) confirmed every program verifies and attaches. The
binding requirements, from strictest to loosest:

| Requirement | Since |
|---|---|
| `BPF_MAP_TYPE_RINGBUF` | 5.8 |
| BTF-typed raw tracepoints (`tp_btf`) | 5.5 |
| `bpf_ktime_get_boot_ns` | 5.7 |
| `bpf_get_current_cgroup_id` | 4.18 |
| CO-RE / `CONFIG_DEBUG_INFO_BTF` | distribution-dependent |
| `oom:mark_victim` with `uid`/`pgtables`/`oom_score_adj` | fields added over time; read with `bpf_core_field_exists` |

## Decision

The hard floor is **5.8**, set by `BPF_MAP_TYPE_RINGBUF`. SPEC.md §3 mandates
ring buffers over perf buffers so that drops are countable, so this is not
negotiable without changing the transport.

The *tested* floor is current Fedora and Fedora N-1. RHEL 9 (5.14) and
RHEL 10 are above the hard floor and expected to work; they are not in CI.

`wake doctor` checks the ring-buffer requirement explicitly and reports it as
fatal with the version that introduced it, so a user on an older kernel gets a
sentence rather than a verifier error.

## Consequences

- No fallback to perf buffers, and no fallback compilation path for kernels
  without BTF. Both were already SPEC non-goals; this records the version at
  which that becomes concrete.
- Tracepoint fields that were added over time are read with
  `bpf_core_field_exists` rather than assumed, so a 5.8 kernel yields a
  partially-populated OOM record rather than a load failure.
