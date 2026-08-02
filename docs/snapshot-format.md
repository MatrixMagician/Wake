# Wake snapshot format

**Status:** versioned public contract. `schema_version` (currently **1**) governs the
whole snapshot and is carried in `manifest.json`. Any change that an existing reader
could misinterpret bumps this number; readers should refuse (or degrade gracefully
for) a `schema_version` they do not recognise.

This document is written so that a consumer can be implemented from this file
alone, without reading Wake's source.

---

## 1. What a snapshot is

A snapshot is a self-contained directory:

```
/var/lib/wake/snapshots/<id>/
├── manifest.json
├── events.jsonl.zst
├── system.json
└── proc/                  # present only if a triggering PID was known
    ├── status
    ├── limits
    ├── cgroup
    ├── cmdline
    └── fd_listing.txt
```

- `<id>` has the shape `<RFC3339-ish timestamp>-<trigger-type>`, e.g.
  `20260802T142007Z-watched-process`. The timestamp component is the trigger's
  firing time in UTC, formatted `YYYYMMDDTHHMMSSZ` (RFC 3339's `date-time`
  production with the `:` separators removed and sub-second precision dropped, so
  the string is a safe path component on every filesystem Wake targets). Because
  the timestamp is zero-padded and UTC, **directory names sort lexically in
  chronological order**.
- The directory and everything under it is created with mode **0700**. This is a
  hard requirement (CLAUDE.md: "Snapshots are 0700"), not a default that operators
  are expected to tighten.
- A snapshot directory is either completely absent or completely present: Wake
  writes to a hidden staging directory beside the final path
  (`.<id>.tmp/`) and publishes with a single `rename(2)`, so a reader that lists
  `/var/lib/wake/snapshots/` and finds a directory **not** starting with `.` can
  assume it is fully written. A directory name beginning with `.` is always a
  write in progress (or a crashed one) and must never be treated as a snapshot.

A missing `proc/` directory is normal and expected: the triggering process may
already have exited before the scrape ran, and the manifest's `proc.found` field
tells a reader whether that happened (§2.6).

---

## 2. `manifest.json`

The single file a reader should open first. Every field below is always present
unless marked optional. Example (see §7 for a full worked example):

```json
{
  "schema_version": 1,
  "id": "20260802T142007Z-watched-process",
  "wake_version": "v0.9.2",
  "generated_at": "2026-08-02T14:20:07.512Z",
  "trigger": { "...": "see 2.2" },
  "host": { "...": "see 2.3" },
  "capture_window": { "...": "see 2.4" },
  "event_count": 842,
  "event_counts": { "exec": 3, "exit": 1, "signal": 0, "oom": 0, "open": 812, "connect": 26, "generic": 0 },
  "drops": { "...": "see 2.5" },
  "config_hash": "3f9a1c...",
  "proc": { "...": "see 2.6, present only if a triggering PID was known" }
}
```

### 2.1 Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer | Governs this whole snapshot. Currently `1`. |
| `id` | string | The snapshot's directory name, repeated here so the manifest is self-identifying if copied out of its directory. |
| `wake_version` | string | The build-stamped version of the `wake` binary that wrote this snapshot. |
| `generated_at` | RFC 3339 timestamp, UTC | When the manifest was written — after the ring was frozen and events serialised, so it is at or after every timestamp in `capture_window`. |
| `trigger` | object | See §2.2. |
| `host` | object | See §2.3. |
| `capture_window` | object | See §2.4. |
| `event_count` | integer | Total events in `events.jsonl.zst`. |
| `event_counts` | object (string→integer) | Per-class breakdown. **Every known class is present, including zero counts** — a class absent from this snapshot is distinguishable from a class that was never checked, mirroring the drop-report convention in §2.5. Keys are the class names from §3.1. |
| `drops` | object | The full drop report at freeze time. See §2.5. |
| `config_hash` | string | Identifies the configuration in force when this snapshot was captured. Opaque to readers; use it to tell "same config" from "different config" across snapshots, not to reconstruct the config. |
| `proc` | object, optional | Present if and only if the trigger carried a PID (i.e. `trigger.pid` is set). See §2.6. |

### 2.2 `trigger`

```json
{
  "type": "watched-process",
  "reason": "exit code 137",
  "rule": "mstr-crash",
  "pid": 4321,
  "unit": "mstr.service",
  "fired_at": "2026-08-02T14:20:06.998Z"
}
```

| Field | Type | Meaning |
|---|---|---|
| `type` | string | One of `watched-process`, `oom`, `signal`, `manual`, `systemd-unit-failed` (SPEC.md §2 goal 4). Treat unrecognised values as forward-compatible extension points, not errors. |
| `reason` | string, optional | Free-text explanation, e.g. supplied via `wake trigger --reason`. |
| `rule` | string, optional | The name/id of the configured rule that matched, if any. |
| `pid` | integer, optional | The triggering process, for process-scoped triggers. |
| `unit` | string, optional | The triggering systemd unit, for unit-scoped triggers. |
| `fired_at` | RFC 3339 timestamp, UTC | When the trigger condition was observed. This seeds the snapshot `id`'s timestamp component. |

### 2.3 `host`

```json
{ "hostname": "mstr-prod-07", "kernel_release": "6.10.0-1.fc42.x86_64", "machine": "x86_64" }
```

A lightweight, always-present host identity (hostname, kernel release, CPU
architecture as reported by `uname(2)`) so a manifest alone identifies which
machine a snapshot came from. Fuller point-in-time system state lives in
`system.json` (§4).

### 2.4 `capture_window`

```json
{ "first_event_ts": "2026-08-02T14:18:37.001002003Z", "last_event_ts": "2026-08-02T14:20:06.998112233Z" }
```

The timestamps of the first and last event actually present in
`events.jsonl.zst`. **Both fields are absent (the whole `capture_window` object is
`{}`) when the snapshot contains zero events** — a manual trigger with nothing
interesting in the ring is valid and produces an empty-but-well-formed snapshot.

### 2.5 `drops`

The full, unabridged drop report: `boundary → class → count`, copied verbatim from
the daemon's live counters at the moment the ring was frozen for this trigger.

```json
{
  "kernel_ringbuf":  { "exec": 0, "exit": 0, "signal": 0, "oom": 0, "open": 0,  "connect": 0, "generic": 0 },
  "decode":          { "exec": 0, "exit": 0, "signal": 0, "oom": 0, "open": 0,  "connect": 0, "generic": 0 },
  "userspace_ring":  { "exec": 0, "exit": 0, "signal": 0, "oom": 0, "open": 12, "connect": 0, "generic": 0 },
  "watch_fanout":    { "exec": 0, "exit": 0, "signal": 0, "oom": 0, "open": 0,  "connect": 0, "generic": 0 }
}
```

**Every boundary and every class is always present, including zero counters.**
This is deliberate (CONTEXT.md, "Drop"): a reader must be able to tell "nothing was
lost at this boundary for this class" apart from "this boundary/class combination
was never reported at all". If a boundary or class you expect is missing from this
object, that indicates an older snapshot from before that boundary/class existed —
check `schema_version`.

| Boundary | Meaning |
|---|---|
| `kernel_ringbuf` | Events the BPF ring buffer could not accept (kernel-side reserve failure), read from a BPF map. |
| `decode` | Records the userspace decoder could not turn into even a generic event. Should always be zero; non-zero indicates a decoder bug. |
| `userspace_ring` | Events evicted from the bounded userspace ring before this snapshot could capture them (overwritten by newer events). This is the boundary most likely to be non-zero under sustained load. |
| `watch_fanout` | Events not delivered to a `wake watch` client because it could not keep up. `watch` is a tuning aid and always loses before the recorder does; non-zero here has no bearing on snapshot completeness. |

Counters are cumulative since daemon start, not since the previous snapshot. A
consumer wanting a delta between two snapshots subtracts the earlier report from
the later one, field by field (values only ever increase within one daemon
lifetime).

### 2.6 `proc`

```json
{ "pid": 4321, "found": true, "files": ["cgroup", "cmdline", "limits", "status", "fd_listing.txt"] }
```

| Field | Type | Meaning |
|---|---|---|
| `pid` | integer | The PID that was scraped (copied from `trigger.pid`). |
| `found` | boolean | Whether the process still existed in `/proc` when the scrape ran. `false` is a normal outcome for a short-lived process — the ring's history is the point, not a live process — and means the `proc/` directory is absent or contains no files. |
| `files` | array of string | Which files under `proc/` were successfully captured, in the fixed set `status`, `limits`, `cgroup`, `cmdline`, `fd_listing.txt`. A file can be legitimately missing from this list (the process raced the scrape) without `found` being `false`. |

---

## 3. `events.jsonl.zst`

Zstandard-compressed newline-delimited JSON. Decompress with any standard zstd
decoder, then read line by line — each line is one complete, self-contained JSON
object with no trailing comma and no enclosing array.

**Ordering guarantee:** events are written **oldest first**, sorted ascending by
the `ts` field, regardless of the order they were observed or the order the caller
supplied them in. This ordering is a contract a reader may rely on rather than a
happenstance of implementation. Where two events share exactly the same
`ts` (possible at nanosecond resolution during a hot burst), their relative order
is unspecified but stable within one file (a stable sort was used).

Each line is exactly what `event.Event.MarshalJSONLine` (Wake's canonical event
type) produces — the same serialisation `wake watch` prints live, so a persisted
snapshot and a live tail can never drift from one another.

**Absent-field convention:** every field is tagged `omitempty` in the Go source.
A field that does not apply to a given event's class (e.g. `argv` on a `connect`
event) is simply **absent from the JSON object**, never present as `null` or a
zero value. The one deliberate exception is the `Enrichment` fields (`comm`,
`cgroup`, `unit`, `container`, `user`, `ppid`, `ancestors`): an *empty* value there
means "not known", never "not applicable" — see §3.3.

### 3.1 Fields common to every event

| JSON field | Type | Meaning |
|---|---|---|
| `ts` | RFC 3339 timestamp, nanosecond precision, UTC (`Z` suffix) | When the kernel observed the event. |
| `class` | string | One of `exec`, `exit`, `signal`, `oom`, `open`, `connect`, or `generic` for an event whose layout the decoder did not recognise. Decode is total: a `generic` event is never dropped, and always carries its raw payload (§3.7). |
| `pid` | integer | The process ID. |
| `tid` | integer, optional | The thread ID, when it differs meaningfully from `pid` and the class captures it. |
| `uid` | integer | The process's UID at the time of the event. |
| `cgroup_id` | integer, optional | The kernel cgroup ID at the time of the event (a raw kernel identifier, not a path — the path lives in the enrichment triple, §3.3). |

### 3.2 Class-specific fields

**`exec`**

| Field | Type | Meaning |
|---|---|---|
| `filename` | string | The executable path passed to `execve(2)`. |
| `argv` | array of string, optional | The argument vector. Subject to configured redaction (§5) *before* it ever reaches disk. |
| `argv_truncated` | boolean, optional | `true` if `argv` was truncated in-kernel (a bounded-size buffer, per SPEC.md's in-kernel-truncation design). Absent (never `false`) when not truncated. |

**`exit`**

| Field | Type | Meaning |
|---|---|---|
| `exit_code` | integer, optional | The process's exit code, if it exited normally. |
| `exit_signal` | integer, optional | The signal number that terminated the process, if it did not exit normally. At most one of `exit_code`/`exit_signal` is present for a given event. |

**`signal`**

| Field | Type | Meaning |
|---|---|---|
| `signal` | integer, optional | The signal number delivered. |
| `signal_name` | string, optional | The signal's symbolic name, e.g. `SIGSEGV`. |
| `sender_pid` | integer, optional | The PID that sent the signal, when the kernel reports it. |

**`oom`**

| Field | Type | Meaning |
|---|---|---|
| `total_vm_kb` | integer, optional | The killed process's total virtual memory, kilobytes. |
| `anon_rss_kb` | integer, optional | Anonymous resident set size, kilobytes. |
| `file_rss_kb` | integer, optional | File-backed resident set size, kilobytes. |
| `oom_score_adj` | integer, optional | The process's `oom_score_adj` at the time of the kill. |

**`open`**

| Field | Type | Meaning |
|---|---|---|
| `path` | string, optional | The path passed to the open attempt. Subject to configured redaction (§5) *before* it ever reaches disk. Both successful and failed attempts are recorded (SPEC.md §2 goal 1). |
| `path_truncated` | boolean, optional | `true` if `path` was truncated in-kernel. |
| `flags` | string, optional | The open flags, rendered symbolically (e.g. `O_RDONLY\|O_CLOEXEC`). |
| `ret` | integer, optional | The syscall's return value. Negative on failure. See §3.4. |
| `errno` | string, optional | The symbolic errno name (e.g. `EACCES`) when `ret` is negative. See §3.4. |

**`connect`**

| Field | Type | Meaning |
|---|---|---|
| `saddr` | string, optional | Source address (v4 or v6 textual form). |
| `daddr` | string, optional | Destination address. |
| `sport` | integer, optional | Source port. |
| `dport` | integer, optional | Destination port. |
| `proto` | string, optional | `tcp` (v1 supports TCP connect attempts only — see SPEC.md §2 goal 1 and §9 open question 2 on UDP). |
| `old_state` | string, optional | The TCP state before this transition, from `inet_sock_set_state` (e.g. `SYN_SENT`). |
| `new_state` | string, optional | The TCP state after this transition (e.g. `CLOSE`). |
| `ret` | integer, optional | The connect attempt's result. Negative on failure. See §3.4. |
| `errno` | string, optional | The symbolic errno name when `ret` is negative. See §3.4. |

**Never present:** packet payloads or any content of what was sent/received —
network events are connection metadata only (SPEC.md §2 Non-Goals).

### 3.3 The enrichment triple (present on any class, when known)

| Field | Type | Meaning |
|---|---|---|
| `comm` | string, optional | The process's command name. |
| `ppid` | integer, optional | The parent PID. |
| `ancestors` | array of string, optional | The `comm` chain of ancestors, nearest first, depth-limited. |
| `cgroup` | string, optional | The cgroup path. |
| `unit` | string, optional | The systemd unit, if resolvable from the cgroup path. |
| `container` | string, optional | The container ID (Podman or Kubernetes cgroup layouts), if resolvable. |
| `user` | string, optional | The resolved username for `uid`. |

Enrichment is resolved at **snapshot time**, not at event-observation time, from a
continuously-maintained cache — so a process that already exited before the
trigger fired can still be attributed (CONTEXT.md, "Enrichment cache"). An absent
enrichment field means "not known", never "not applicable": do not infer that a
process has no parent because `ppid` is absent, only that Wake could not resolve
it.

### 3.4 Errno and return-value convention

For classes with an outcome (`open`, `connect`), `ret` is the raw syscall return
value (negative on failure, per Linux convention) and `errno` is the symbolic name
of `-ret` (e.g. `ret: -13, errno: "EACCES"`). Both fields are present together or
both absent; a successful attempt (`ret >= 0`) never carries `errno`.

### 3.5 Redaction

Configured regex patterns are applied to `argv` and `path` **before
serialisation** — a masked value never reaches disk, let alone this file
(SPEC.md §4, CLAUDE.md "Privacy lines are hard requirements"). Redaction is
config, not code: what gets masked and how (e.g. replaced with a fixed string,
partially masked) is controlled by the operator's `/etc/wake/wake.toml`, and this
document makes no promise about *which* patterns are applied by default — only
that whatever the operator configured was applied before the bytes in this file
were written. A snapshot consumer cannot recover a redacted value; it was never
there.

### 3.6 What never appears

- **File contents.** Ever. `open` events record path/flags/errno only —
  never a byte of what was read or written. This is a hard privacy line
  (SPEC.md §2 Non-Goals), not something a config flag can turn back on.
- **Packet contents.** `connect` events are connection metadata only.
- **Anything from `proc/fd_listing.txt` beyond fd number and symlink target**
  (§6.5) — never the contents behind an open fd.

### 3.7 `generic` events

An event whose wire layout the decoder did not recognise becomes `class: "generic"`
rather than being dropped (CONTEXT.md, "Event": "An event that cannot be decoded
into a known class becomes a generic record with its raw payload retained").

| Field | Type | Meaning |
|---|---|---|
| `raw_kind` | integer, optional | The raw, undecoded kind/type tag from the wire format. |
| `raw` | string (base64), optional | The raw payload bytes, base64-encoded by Go's standard `encoding/json` `[]byte` marshalling. This is the one place raw kernel bytes appear in a snapshot; they are opaque payload metadata about an unrecognised record shape, not file or packet contents. |
| `decode_error` | string, optional | A human-readable explanation of why this record could not be decoded into a known class. |

A `generic` event may still carry any of the common fields (§3.1) and the
enrichment triple (§3.3) if the decoder recovered that much before giving up.

---

## 4. `system.json`

Point-in-time host state captured at trigger time, distinct from the always-present
`host` summary in the manifest (§2.3). Every sub-object here is **best-effort**:
`system.json` is diagnostic context, not load-bearing evidence like the event
stream or the drop report, so a field being absent because the underlying `/proc`
file did not exist on this kernel is normal, not an error.

```json
{
  "captured_at": "2026-08-02T14:20:07.001Z",
  "uname": {
    "sysname": "Linux", "nodename": "mstr-prod-07",
    "release": "6.10.0-1.fc42.x86_64", "version": "#1 SMP PREEMPT_DYNAMIC ...",
    "machine": "x86_64"
  },
  "meminfo": { "MemTotal": "16384000 kB", "MemFree": "2048000 kB", "...": "..." },
  "pressure": {
    "memory": { "some": {"avg10": "0.50", "avg60": "0.20", "avg300": "0.10", "total": "12345"},
                "full": {"avg10": "0.10", "avg60": "0.05", "avg300": "0.01", "total": "6789"} },
    "cpu":    { "some": {"avg10": "1.20", "avg60": "0.80", "avg300": "0.30", "total": "99999"} }
  },
  "uptime_seconds": 123456.78,
  "loadavg": [0.10, 0.20, 0.30]
}
```

| Field | Type | Meaning |
|---|---|---|
| `captured_at` | RFC 3339 timestamp, UTC | When this file's contents were read — may differ by a small amount from `manifest.generated_at`. |
| `uname` | object | `sysname`, `nodename`, `release`, `version`, `machine`, verbatim from `uname(2)`. |
| `meminfo` | object (string→string), optional | The full contents of `/proc/meminfo`, one entry per line, key with the trailing `:` stripped, value **including any unit suffix exactly as the kernel wrote it** (e.g. `"16384000 kB"`) — Wake does not parse units or convert them. |
| `pressure` | object, optional | Present resources: any of `cpu`, `memory`, `io`. A resource is **absent from this object** if `/proc/pressure/<resource>` did not exist (PSI disabled for that resource, or a kernel that predates PSI) — this is expected, not an error. Each present resource has a `some` object and, where the kernel provides it, a `full` object (CPU has no `full` line, since "all tasks stalled" is not a meaningful concept for CPU pressure). Each of `some`/`full` is a verbatim string map of the kernel's own field names: `avg10`, `avg60`, `avg300`, `total`. Values are passed through as strings deliberately, not parsed into numbers, so a future kernel field is captured rather than silently dropped by a struct that does not know about it yet. |
| `uptime_seconds` | number | `/proc/uptime`'s first field: seconds since boot. |
| `loadavg` | array of 3 numbers | `/proc/loadavg`'s three load averages (1/5/15 minute). |

---

## 5. `proc/`

A scrape of the triggering process's `/proc/<pid>/` entry, present only when the
trigger carried a PID **and** the process still existed when the scrape ran
(`manifest.proc.found == true`). Every file here is metadata about the process —
**never the contents of anything the process had open** (CLAUDE.md: "No file
contents, ever"). This is the strictest privacy line in the whole snapshot format;
see §6.5 for exactly how the fd listing avoids crossing it.

| File | Source | Contents |
|---|---|---|
| `status` | `/proc/<pid>/status`, verbatim | Human-readable process status: name, state, memory, signal masks, etc. |
| `limits` | `/proc/<pid>/limits`, verbatim | `RLIMIT_*` soft/hard limits. |
| `cgroup` | `/proc/<pid>/cgroup`, verbatim | The process's cgroup membership line(s). |
| `cmdline` | `/proc/<pid>/cmdline`, verbatim | The NUL-separated command line as the kernel holds it (**not** re-derived from the `exec` event's `argv`, and **not** subject to the same redaction patterns as `events.jsonl.zst` unless the operator has separately configured proc-scrape redaction — treat this file as sensitive by default). |
| `fd_listing.txt` | Derived, plain text | See §6.5. |

Any of these five files can be legitimately absent even when `found == true`: the
process can exit between the scrape starting and a given file being read, and a
partial scrape is recorded as such rather than failing the whole snapshot
(`manifest.proc.files` lists exactly what was captured).

### 5.1 `fd_listing.txt`

Tab-separated, one open file descriptor per line: `<fd number>\t<symlink target>`.

```
0	/dev/null
1	socket:[48213]
2	/var/log/mstr/error.log
3	pipe:[48214]
```

This is **not** a copy of `/proc/<pid>/fdinfo/<fd>` (which the kernel's own format
can include offsets and flags that read closer to "what the process was doing"
than this contract wants to commit to indefinitely) and it is emphatically **not**
the contents of any of these targets. It is exactly what `readlink()` on
`/proc/<pid>/fd/<fd>` returns for each open descriptor: the fd number and what it
points to, nothing more. A target being a regular file path tells you the process
had that file open; it tells you nothing about what is in it.

---

## 6. Versioning policy

- `manifest.schema_version` governs the entire snapshot — every file within it,
  not just `events.jsonl.zst`.
- A **backwards-compatible** change (a new optional field, a new event class, a new
  trigger type, a new drop boundary) does **not** require a version bump. Readers
  must already tolerate unknown fields and unknown enum-like string values
  (`class`, `trigger.type`, drop boundary/class names) by ignoring what they don't
  recognise, per standard "be liberal in what you accept" JSON practice.
- A change that could cause an existing reader to **misinterpret** data — a field
  changing type or meaning, a field being removed, an ordering guarantee being
  relaxed, a privacy boundary moving — bumps `schema_version` and is called out in
  `CHANGELOG` / release notes.
- There is no promise of forward compatibility: a reader built against schema
  version *N* is not guaranteed to understand version *N+1*'s new required
  semantics, only that it can detect the mismatch by checking
  `manifest.schema_version` before trusting the rest of the file.

---

## 7. Worked example

A complete, minimal, hand-checkable snapshot with this shape is committed at
`testdata/fixtures/reference-snapshot/` for exactly this purpose — decompress
`events.jsonl.zst` with any zstd tool and read every file directly. Below is the
same snapshot's `manifest.json` reproduced inline as a quick-reference example (see
the fixture's own `README.md` for the full byte-for-byte contents and the schema
test that validates it, `internal/snapshot/fixture_test.go`).

```json
{
  "schema_version": 1,
  "id": "20260802T142006Z-watched-process",
  "wake_version": "v0.9.2-fixture",
  "generated_at": "2026-08-02T14:20:07.5Z",
  "trigger": {
    "type": "watched-process",
    "reason": "exit code 137",
    "rule": "mstr-crash",
    "pid": 4321,
    "unit": "mstr.service",
    "fired_at": "2026-08-02T14:20:06.998Z"
  },
  "host": {
    "hostname": "fixture-host",
    "kernel_release": "6.10.0-fixture",
    "machine": "x86_64"
  },
  "capture_window": {
    "first_event_ts": "2026-08-02T14:20:04.1Z",
    "last_event_ts": "2026-08-02T14:20:06.998Z"
  },
  "event_count": 3,
  "event_counts": {
    "connect": 0, "exec": 1, "exit": 1, "generic": 0, "oom": 0, "open": 1, "signal": 0
  },
  "drops": {
    "kernel_ringbuf": {"connect": 0, "exec": 0, "exit": 0, "generic": 0, "oom": 0, "open": 0, "signal": 0},
    "decode":         {"connect": 0, "exec": 0, "exit": 0, "generic": 0, "oom": 0, "open": 0, "signal": 0},
    "userspace_ring": {"connect": 0, "exec": 0, "exit": 0, "generic": 0, "oom": 0, "open": 0, "signal": 0},
    "watch_fanout":   {"connect": 0, "exec": 0, "exit": 0, "generic": 0, "oom": 0, "open": 0, "signal": 0}
  },
  "config_hash": "fixture0000000000000000000000000000000000000000000000000000000",
  "proc": {
    "pid": 4321,
    "found": true,
    "files": ["cgroup", "cmdline", "limits", "status", "fd_listing.txt"]
  }
}
```

The corresponding `events.jsonl.zst` decompresses to three lines, oldest first:

```json
{"ts":"2026-08-02T14:20:04.1Z","class":"exec","pid":4321,"uid":1000,"comm":"smtpd","cgroup":"/system.slice/mstr.service","unit":"mstr.service","filename":"/usr/sbin/smtpd","argv":["smtpd","-d"]}
{"ts":"2026-08-02T14:20:05.25Z","class":"open","pid":4321,"uid":1000,"comm":"smtpd","cgroup":"/system.slice/mstr.service","unit":"mstr.service","path":"/etc/ssl/certs/mstr.pem","flags":"O_RDONLY","ret":-13,"errno":"EACCES"}
{"ts":"2026-08-02T14:20:06.998Z","class":"exit","pid":4321,"uid":1000,"comm":"smtpd","cgroup":"/system.slice/mstr.service","unit":"mstr.service","exit_signal":9}
```

`system.json` and `proc/*` follow the shapes in §4 and §5 respectively; see the
fixture directory for exact byte-for-byte contents. Note that Go's JSON time
encoding trims trailing zero fractional digits (`.5Z` rather than `.500000000Z`,
`.1Z` rather than `.100000000Z`) — a reader's RFC 3339 parser must accept any
number of fractional-second digits, from none up to nanosecond precision, per
RFC 3339 §5.6.
