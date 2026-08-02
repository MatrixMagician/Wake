/* SPDX-License-Identifier: Apache-2.0 */
/*
 * wake_maps.h — shared maps, filters and emit helpers.
 *
 * Design rule (CLAUDE.md): keep the BPF C minimal and boring. Filtering and
 * truncation happen here, in kernel, because that is the only place they can
 * save work; everything else belongs in Go where it can be unit-tested.
 */
#ifndef WAKE_MAPS_H
#define WAKE_MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "wake_event.h"

char LICENSE[] SEC("license") = "GPL";

/* vmlinux.h carries kernel types, not UAPI constants, so the handful we need
 * are defined here rather than pulled from headers the target need not have. */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

/* The single ring buffer carrying every class to userspace. Sized from config
 * at load time via bpf_map__set_max_entries. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); /* 4 MiB default; overridden by the loader */
} events SEC(".maps");

/* Per-class kernel-side drop counters, indexed by enum wake_kind. A ringbuf
 * reserve failure must be countable, never invisible (CONTEXT.md, "Drop"). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, WAKE_DROP_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

/* Runtime configuration pushed from userspace. A single-entry array rather
 * than constants so that `wake` can retune filters without reloading. */
struct wake_cfg {
	__u64 self_pid;        /* wake's own tgid, always excluded */
	__u64 cgroup_scope;    /* 0 = every cgroup; else only this id and children */
	__u32 classes_enabled; /* bitmask over (1 << wake_kind) */
	__u32 filter_comm;     /* 1 = consult the comm map */
	__u32 comm_is_allow;   /* 1 = map is an allow list, 0 = deny list */
	__u32 filter_path;     /* 1 = consult the path-prefix map */
	__u32 filter_port;     /* 1 = consult the port map */
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wake_cfg);
} wake_config_map SEC(".maps");

/* Cgroup subtree scope: userspace populates every cgroup id in the subtree,
 * because walking ancestors in BPF is bounded-loop awkward and the set is
 * small and changes rarely. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} cgroup_scope SEC(".maps");

struct comm_key {
	char comm[WAKE_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct comm_key);
	__type(value, __u8);
} comm_filter SEC(".maps");

/* Path prefixes are matched on a fixed-length head of the path, so the match
 * is a hash lookup rather than a loop. Userspace pads each configured prefix
 * to WAKE_PREFIX_LEN and inserts every prefix length it needs. */
#define WAKE_PREFIX_LEN 64

struct path_key {
	char prefix[WAKE_PREFIX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct path_key);
	__type(value, __u8);
} path_filter SEC(".maps");

/* Ports of interest for the connect class. Empty map with filter_port set
 * means "record nothing", which is a legitimate, explicit configuration. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);
	__type(value, __u8);
} port_filter SEC(".maps");

/* Signals of interest for the signal class. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} signal_filter SEC(".maps");

/* Per-CPU scratch: wake_exec is far larger than the 512-byte BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wake_exec);
} exec_scratch SEC(".maps");

static __always_inline void wake_count_drop(__u32 kind)
{
	__u32 k = kind & (WAKE_DROP_SLOTS - 1);
	__u64 *v = bpf_map_lookup_elem(&drops, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline struct wake_cfg *wake_config(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&wake_config_map, &z);
}

static __always_inline int wake_class_enabled(struct wake_cfg *cfg, __u32 kind)
{
	return cfg && (cfg->classes_enabled & (1U << kind));
}

/* wake_in_scope applies the cheap, universal filters: never record wake
 * itself (that way lies a feedback loop), and honour the cgroup scope and
 * comm allow/deny list. Returns 1 to record. */
static __always_inline int wake_in_scope(struct wake_cfg *cfg, __u64 cgid,
					 const char *comm)
{
	__u64 tgid = bpf_get_current_pid_tgid() >> 32;

	if (!cfg)
		return 0;
	if (cfg->self_pid && tgid == cfg->self_pid)
		return 0;

	if (cfg->cgroup_scope) {
		__u8 *hit = bpf_map_lookup_elem(&cgroup_scope, &cgid);
		if (!hit)
			return 0;
	}

	if (cfg->filter_comm) {
		struct comm_key key = {};
		__builtin_memcpy(key.comm, comm, WAKE_COMM_LEN);
		__u8 *hit = bpf_map_lookup_elem(&comm_filter, &key);
		if (cfg->comm_is_allow ? !hit : !!hit)
			return 0;
	}

	return 1;
}

static __always_inline void wake_fill_header(struct wake_header *h, __u32 kind)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	h->ts_ns = bpf_ktime_get_boot_ns();
	h->kind = kind;
	h->wire_ver = WAKE_WIRE_VERSION;
	h->pid = id >> 32;
	h->tid = (__u32)id;
	h->uid = (__u32)uid_gid;
	h->_pad = 0;
	h->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&h->comm, sizeof(h->comm));
}

#endif /* WAKE_MAPS_H */
