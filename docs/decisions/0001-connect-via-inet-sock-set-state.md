# 0001. Capture TCP connect attempts via `inet_sock_set_state`, not kprobes

## Status

Accepted. Resolves SPEC.md §10 open question 1.

## Context

SPEC.md §3 prefers stable tracepoints over kprobes, and §8 requires a decision
record for any kprobe use. Open question 1 asked whether
`sock:inet_sock_set_state` actually yields failed connect attempts *with an
errno*, or whether `tcp_v4_connect`/`tcp_v6_connect` kprobes would be needed.

The tracepoint's format on 7.1.5-201.fc44.x86_64 was read directly:

```
field:const void * skaddr;  offset:8;   size:8;
field:int oldstate;         offset:16;  size:4;
field:int newstate;         offset:20;  size:4;
field:__u16 sport;          offset:24;  size:2;
field:__u16 dport;          offset:26;  size:2;
field:__u16 family;         offset:28;  size:2;
field:__u16 protocol;       offset:30;  size:2;
field:__u8 saddr[4];        offset:32;  size:4;
field:__u8 daddr[4];        offset:36;  size:4;
field:__u8 saddr_v6[16];    offset:40;  size:16;
field:__u8 daddr_v6[16];    offset:56;  size:16;
```

There is no errno field, and there will not be one: the tracepoint reports
socket *state transitions*, not syscall results.

## Decision

Use `sock:inet_sock_set_state` and infer the outcome from the transition:

| Transition | Meaning |
|---|---|
| `TCP_CLOSE` → `TCP_SYN_SENT` | a connect attempt started |
| `TCP_SYN_SENT` → `TCP_ESTABLISHED` | it succeeded |
| `TCP_SYN_SENT` → `TCP_CLOSE` | it failed |

A failed attempt is reported with the errno field set to the honest value
`ECONNREFUSED_OR_TIMEOUT`, because the transition genuinely cannot distinguish
the two. Inventing a specific errno would be worse than admitting the
ambiguity: an incident report that says `ECONNREFUSED` when the truth was a
timeout sends the reader down the wrong path.

Kprobes on `tcp_v4_connect`/`tcp_v6_connect` *would* give the exact return
value, at the cost of: an unstable interface that changes across kernels, a
second attach point per address family, and a decision record justifying why
the tracepoint was insufficient. It is not insufficient — it is merely less
precise in one field — and the timing evidence (SYN_SENT dwell time) usually
distinguishes refusal from timeout anyway.

Also note the sport/dport on this tracepoint are already in host byte order,
unlike most socket paths. This is recorded here because it is exactly the kind
of detail that gets "fixed" into a bug by someone adding an `ntohs`.

## Consequences

- No kprobes anywhere in Wake, so no kernel-version-specific attach logic.
- Failed connects carry an ambiguous-but-honest errno. If a future user needs
  the exact value badly enough, the decision to add a kprobe is a scoped one
  affecting only the connect class, and this record is where it starts.
- Listening sockets and inbound connections also produce transitions. They are
  recorded, and are frequently useful: "the service stopped listening" is an
  incident finding.
