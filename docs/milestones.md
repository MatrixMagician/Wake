# Milestone status

Audit of the implementation against SPEC.md §7. Each criterion is marked with
the evidence that discharges it, so that a reader can check rather than trust.

Verified on Fedora 44, kernel 7.1.5-201.fc44.x86_64, Go 1.26.

Gates, all currently green:

- `go vet` clean.
- `golangci-lint` clean (0 issues), policy stated in `.golangci.yml`.
- `go test -race ./...` across 10 packages.
- `make integration` as root: 18 tests against the live kernel.
- `testdata/smoke.sh`: full daemon lifecycle end to end.
- `make perf`: 0.200% CPU and 27.3 MiB RSS at 10k events/s, zero drops.
- Decoder fuzzing: 59 million executions, no panic, no unserialisable event.

---

## M1 — Skeleton + exec/exit pipeline end-to-end ✔

| Criterion | Evidence |
|---|---|
| bpf2go build embeds objects | `internal/loader/gen.go`, `make generate`; binary is `CGO_ENABLED=0`, needs no clang on target |
| Daemon loads exec/exit tracepoints, decodes into the ring | `internal/loader/loader.go`, `internal/recorder/recorder.go` |
| `wake watch` shows live events | verified in `testdata/smoke.sh` ("watch streams events") |
| `doctor` reports BTF/caps/tracepoint bindability | `internal/doctor/doctor.go`; nine checks, each carrying its remedy |
| Integration test proves an exec'd fixture appears with correct argv | `TestExecEventEndToEnd` |
| Truncation case included | `TestDecodeExecTruncatedArgv`, plus `TestDecodeExecBogusArgvLen` for a corrupt length field |
| Drop counters wired even if zero | `TestKernelDropCountersAreReadable`; all four boundaries present in every manifest |

## M2 — Ring semantics + enrichment cache + status ✔

| Criterion | Evidence |
|---|---|
| Ring honours time/count/memory bounds | `internal/ring/ring_test.go`, property tests with a fixed seed |
| Property tests on eviction order | ibid. |
| Load generator in-repo | `testdata/loadgen/loadgen.go`, `measure.sh` |
| Process that exited 30 s ago still attributable | `TestExitedProcessStaysAttributable` |
| Podman and raw-systemd cgroup layouts fixture-tested | `internal/enrich/cgroup_test.go` + `testdata/cgroups/`; Docker and Kubernetes covered too |
| `status` complete | `internal/ctl/protocol.go`, rendered by `internal/cli/client.go`; leads with drops |

## M3 — Remaining event classes + in-kernel filtering ✔

| Criterion | Evidence |
|---|---|
| signal/oom/openat/connect implemented against verified layouts | `bpf/wake.bpf.c`; offsets cited in `bpf/wake_event.h` from this kernel's `format` files |
| Provenance comments citing the running kernel | ibid., and `docs/decisions/0001-connect-via-inet-sock-set-state.md` quotes the format file verbatim |
| Filters demonstrably drop events **in kernel** | `internal/loader/filter_integration_test.go` — comm, path prefix, signal and cgroup scope, each with a vacuity guard proving the negative case is not passing trivially |
| Overhead budget met at 10k events/s | `docs/perf.md`: 0.200% CPU (budget 1%), 27.3 MiB RSS (budget 128 MiB), zero drops |
| Measured and enforced by a script | `make perf` exits non-zero over budget |

**Note.** CIDR filtering is applied in userspace, not in kernel. This is a
deliberate, recorded decision (`docs/decisions/0002-cidr-filtering-in-userspace.md`)
rather than an omission: the connect class is the lowest-volume one, so an LPM
trie per address family buys a negligible number of avoided crossings for
meaningful BPF complexity.

## M4 — Trigger engine + snapshot writer ✔

| Criterion | Evidence |
|---|---|
| All five trigger types fire | `internal/trigger/trigger_test.go` for four; `TestUnitFailureTriggerViaSDBus` for the fifth |
| sd-bus unit-failure via a purposely-failing test unit | ibid. — a real transient unit on the real system bus |
| Trigger→snapshot with recording uninterrupted | `TestRecordingContinuesThroughAFreeze`; freeze is an O(1) buffer swap |
| Events during writing appear in the *next* ring | ibid. |
| Snapshot contains manifest, zstd JSONL, system.json, proc/ | `internal/snapshot/`, asserted in `testdata/smoke.sh` |
| Cooldown prevents storming | `TestCooldownPreventsStorms` — 40 crashes produce 1 snapshot and a suppression count of 39 |
| Accurate drop stats mid-load | drop report is captured at freeze and copied verbatim into the manifest |

## M5 — Redaction + retention + snapshot contract ✔

| Criterion | Evidence |
|---|---|
| Masked values never reach disk | `TestRedactedValuesNeverReachDisk` — asserts on the decompressed bytes of every file in a written snapshot, mutation-verified |
| Retention pruning by count and size | `internal/snapshot/retention_test.go` |
| Format documented to adapter-from-doc-alone standard | `docs/snapshot-format.md` |
| Reference fixture snapshot committed | `testdata/fixtures/reference-snapshot/` |
| Validated by a schema test | `internal/snapshot/fixture_test.go` |

Redaction is applied **on the way into the ring**, not at snapshot time. That
is stronger than the SPEC requires: a secret that never enters the ring cannot
leak through a `wake watch` stream either, and there is one code path rather
than two.

## M6 — Hardening + packaging + release ◐

| Criterion | Status |
|---|---|
| Hardened systemd unit ships | ✔ `deploy/wake.service` |
| Documented what had to be loosened and why | ✔ `docs/decisions/0003-systemd-sandboxing.md` — five settings, each with its reason |
| `doctor` detects and explains known failure modes | ✔ including the `unprivileged_bpf_disabled` red herring and an SELinux `ausearch` hint |
| README with a worked incident walkthrough | ✔ `README.md` |
| Daemon runs under the unit, integration-verified | ◐ the unit is written and its sandboxing reasoned through, but it has not been installed and exercised on this box |
| goreleaser static binaries | ✔ `.goreleaser.yaml`; verified with a snapshot build producing static amd64 and arm64 binaries plus RPM and DEB packages. The extracted binary was run: `--version` stamped, `doctor` passed, and it recorded and snapshotted correctly. |
| CI | ✔ `.github/workflows/ci.yml` (build, unit tests with `-race`, decoder fuzzing, lint, integration on a live kernel, smoke test, informational perf) and `release.yml` (gated on the tests passing) |

## M7 — Consumption contract ✔

| Criterion | Evidence |
|---|---|
| SPEC states who the consumer is and what Wake ships | SPEC.md §6.1–6.2; decision recorded in `docs/decisions/0009` |
| Consumer obligations stated normatively | SPEC.md §6.3 and `docs/snapshot-format.md` §6 — check `schema_version`, ignore dot-prefixed dirs, surface non-zero drops, tolerate the unknown |
| Compatibility promise stated and enforced | SPEC.md §6.4; `CHANGELOG.md` carries the schema history; the fixture test names a serialisation change as a breaking change rather than a stale fixture. Mutation-verified by bumping `SchemaVersion` and by renaming a JSON tag |
| Fixture exercises every event class | `testdata/fixtures/reference-snapshot/` — 8 events across all 7 classes including `generic`, plus a non-zero drop count so the drop-surfacing obligation can be exercised |
| Fixture is regenerable | `make fixture` from `internal/snapshot/mkfixture`; byte-for-byte reproducible, verified by regenerating twice and comparing checksums |

---

## Outstanding

1. **Install and run under the shipped unit.** The sandboxing decisions in ADR
   0003 were derived from how BPF and systemd interact, not from having watched
   this unit fail and be fixed. Until the daemon has run under it, that ADR is
   reasoning rather than evidence.
2. **goreleaser configuration** for tagged static builds.

## Open questions

All six from SPEC.md §10 are resolved in `docs/decisions/0001`–`0008`.
