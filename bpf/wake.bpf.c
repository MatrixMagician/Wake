/* SPDX-License-Identifier: Apache-2.0 */
/*
 * wake.bpf.c — all of Wake's BPF programs.
 *
 * Every tracepoint layout below was verified against the running kernel
 * (7.1.5-201.fc44.x86_64) by reading
 * /sys/kernel/tracing/events/<subsystem>/<event>/format; the field offsets are
 * cited in wake_event.h next to the struct that mirrors them. Do not code
 * tracepoint fields from memory (CLAUDE.md).
 *
 * We use BTF-typed raw tracepoints (tp_btf) where available because they are
 * cheaper than the classic format-based tracepoints and give us typed access
 * to the kernel structures, and classic syscall tracepoints for openat, which
 * has no raw-tracepoint equivalent.
 */
#include "wake_maps.h"

/* ------------------------------------------------------------------ exec */

/*
 * argv is not carried by sched_process_exec, so we read it from the new mm's
 * [arg_start, arg_end) range, which is populated by the time the tracepoint
 * fires. The read is bounded by WAKE_ARGV_LEN and truncation is flagged, never
 * silent.
 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(wake_exec_prog, struct task_struct *task, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct wake_cfg *cfg = wake_config();
	struct wake_exec *e;
	__u32 zero = 0;
	__u64 cgid = bpf_get_current_cgroup_id();
	char comm[WAKE_COMM_LEN];

	if (!wake_class_enabled(cfg, WAKE_KIND_EXEC))
		return 0;
	bpf_get_current_comm(&comm, sizeof(comm));
	if (!wake_in_scope(cfg, cgid, comm))
		return 0;

	e = bpf_map_lookup_elem(&exec_scratch, &zero);
	if (!e)
		return 0;

	wake_fill_header(&e->hdr, WAKE_KIND_EXEC);
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->argv_trunc = 0;
	e->argv_len = 0;
	e->filename[0] = '\0';
	e->argv[0] = '\0';

	{
		const char *fn = BPF_CORE_READ(bprm, filename);
		if (fn)
			bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
	}

	{
		struct mm_struct *mm = BPF_CORE_READ(task, mm);
		unsigned long start = 0, end = 0;
		__u64 len;

		if (mm) {
			start = BPF_CORE_READ(mm, arg_start);
			end = BPF_CORE_READ(mm, arg_end);
		}
		if (end > start) {
			len = end - start;
			if (len > WAKE_ARGV_LEN) {
				len = WAKE_ARGV_LEN;
				e->argv_trunc = 1;
			}
			/* Bound the length for the verifier's benefit. */
			len &= (WAKE_ARGV_LEN - 1);
			if (len > 0 &&
			    bpf_probe_read_user(e->argv, len, (void *)start) == 0)
				e->argv_len = len;
		}
	}

	if (bpf_ringbuf_output(&events, e, sizeof(*e), 0) != 0)
		wake_count_drop(WAKE_KIND_EXEC);
	return 0;
}

/* ------------------------------------------------------------------ exit */

/*
 * The exit code is not on the tracepoint; it is task->exit_code, whose low
 * 7 bits are the terminating signal and whose bits 8-15 are the exit status
 * (include/linux/sched.h, and the same encoding wait(2) documents).
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(wake_exit_prog, struct task_struct *task)
{
	struct wake_cfg *cfg = wake_config();
	struct wake_exit e = {};
	__u64 cgid = bpf_get_current_cgroup_id();
	char comm[WAKE_COMM_LEN];
	int code;
	pid_t pid, tgid;

	if (!wake_class_enabled(cfg, WAKE_KIND_EXIT))
		return 0;
	bpf_get_current_comm(&comm, sizeof(comm));
	if (!wake_in_scope(cfg, cgid, comm))
		return 0;

	/* Only report the death of the thread group leader; individual threads
	 * exiting are noise for an incident recorder. */
	pid = BPF_CORE_READ(task, pid);
	tgid = BPF_CORE_READ(task, tgid);
	if (pid != tgid)
		return 0;

	wake_fill_header(&e.hdr, WAKE_KIND_EXIT);
	code = BPF_CORE_READ(task, exit_code);
	e.exit_signal = code & 0x7f;
	e.exit_code = (code >> 8) & 0xff;
	e.group_dead = 1;

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0) != 0)
		wake_count_drop(WAKE_KIND_EXIT);
	return 0;
}

/* ---------------------------------------------------------------- signal */

/*
 * signal:signal_deliver fires in the context of the *receiving* task, so the
 * header's pid is the target. The sender is not recoverable from this
 * tracepoint; siginfo's si_pid is, when the signal was sent by a process.
 */
SEC("tp_btf/signal_deliver")
int BPF_PROG(wake_signal_prog, int sig, struct kernel_siginfo *info,
	     struct k_sigaction *ka)
{
	struct wake_cfg *cfg = wake_config();
	struct wake_signal e = {};
	__u64 cgid = bpf_get_current_cgroup_id();
	char comm[WAKE_COMM_LEN];
	__u32 signo = (__u32)sig;

	if (!wake_class_enabled(cfg, WAKE_KIND_SIGNAL))
		return 0;

	/* The signal set is always an allow list: recording every SIGCHLD on a
	 * busy box would drown the ring. */
	if (!bpf_map_lookup_elem(&signal_filter, &signo))
		return 0;

	bpf_get_current_comm(&comm, sizeof(comm));
	if (!wake_in_scope(cfg, cgid, comm))
		return 0;

	wake_fill_header(&e.hdr, WAKE_KIND_SIGNAL);
	e.sig = sig;
	if (info && (long)info > 0) {
		e.code = BPF_CORE_READ(info, si_code);
		e.sender_pid = BPF_CORE_READ(info, _sifields._kill._pid);
	}

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0) != 0)
		wake_count_drop(WAKE_KIND_SIGNAL);
	return 0;
}

/* ------------------------------------------------------------------- oom */

/*
 * oom:mark_victim fires in the context of the killer, not the victim, so the
 * header is rewritten to describe the victim: an OOM record that attributes
 * itself to the kernel thread doing the killing would be worse than useless.
 * Sizes are in kB, per the tracepoint's own print format.
 *
 * This tracepoint gained fields over time (uid, pgtables, oom_score_adj), so
 * each is read with bpf_core_field_exists rather than assumed.
 */
SEC("tp_btf/mark_victim")
int BPF_PROG(wake_oom_prog, struct task_struct *task)
{
	struct wake_cfg *cfg = wake_config();
	struct wake_oom e = {};
	struct mm_struct *mm;

	if (!wake_class_enabled(cfg, WAKE_KIND_OOM))
		return 0;

	/* An OOM kill anywhere in scope is always interesting, so the comm
	 * filter is deliberately not applied here — only the cgroup scope is,
	 * and that is checked against the victim's cgroup by userspace. */
	wake_fill_header(&e.hdr, WAKE_KIND_OOM);
	e.hdr.pid = BPF_CORE_READ(task, tgid);
	e.hdr.tid = BPF_CORE_READ(task, pid);
	bpf_probe_read_kernel_str(&e.hdr.comm, sizeof(e.hdr.comm),
				  BPF_CORE_READ(task, comm));

	mm = BPF_CORE_READ(task, mm);
	if (mm) {
		/* Counters are in pages; convert to kB assuming 4 KiB pages,
		 * matching the tracepoint's own K() macro. */
		e.total_vm_kb = BPF_CORE_READ(mm, total_vm) << 2;
	}
	if (bpf_core_field_exists(task->signal->oom_score_adj))
		e.oom_score_adj = BPF_CORE_READ(task, signal, oom_score_adj);

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0) != 0)
		wake_count_drop(WAKE_KIND_OOM);
	return 0;
}

/* ------------------------------------------------------------------ open */

/*
 * openat needs both ends: sys_enter carries the path and flags, sys_exit
 * carries the result. They are paired through a scratch hash keyed by
 * pid_tgid, so that failing opens keep their errno — the failures are usually
 * the interesting ones. Only paths, flags and results are captured; file
 * contents are never read, and never will be.
 */
struct open_pending {
	__u64 flags;
	char path[WAKE_PATH_LEN];
	__u8 trunc;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct open_pending);
} open_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct open_pending);
} open_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wake_open);
} open_out SEC(".maps");

/* syscalls:sys_enter_openat — dfd @16, filename @24, flags @32, mode @40. */
struct openat_enter_args {
	unsigned long long unused;
	long syscall_nr;
	long dfd;
	const char *filename;
	long flags;
	long mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int wake_openat_enter(struct openat_enter_args *ctx)
{
	struct wake_cfg *cfg = wake_config();
	struct open_pending *p;
	__u32 zero = 0;
	__u64 key = bpf_get_current_pid_tgid();
	__u64 cgid = bpf_get_current_cgroup_id();
	char comm[WAKE_COMM_LEN];
	long n;

	if (!wake_class_enabled(cfg, WAKE_KIND_OPEN))
		return 0;
	bpf_get_current_comm(&comm, sizeof(comm));
	if (!wake_in_scope(cfg, cgid, comm))
		return 0;

	p = bpf_map_lookup_elem(&open_scratch, &zero);
	if (!p)
		return 0;
	p->flags = ctx->flags;
	p->trunc = 0;
	p->path[0] = '\0';

	n = bpf_probe_read_user_str(p->path, sizeof(p->path), ctx->filename);
	if (n < 0)
		return 0;
	if (n == sizeof(p->path))
		p->trunc = 1;

	if (cfg->filter_path) {
		struct path_key pk = {};
		__builtin_memcpy(pk.prefix, p->path, WAKE_PREFIX_LEN);
		if (!bpf_map_lookup_elem(&path_filter, &pk))
			return 0;
	}

	bpf_map_update_elem(&open_pending, &key, p, BPF_ANY);
	return 0;
}

/* syscalls:sys_exit_openat — ret @16. */
struct openat_exit_args {
	unsigned long long unused;
	long syscall_nr;
	long ret;
};

SEC("tracepoint/syscalls/sys_exit_openat")
int wake_openat_exit(struct openat_exit_args *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct open_pending *p = bpf_map_lookup_elem(&open_pending, &key);
	struct wake_open *e;
	__u32 zero = 0;

	if (!p)
		return 0;

	e = bpf_map_lookup_elem(&open_out, &zero);
	if (!e) {
		bpf_map_delete_elem(&open_pending, &key);
		return 0;
	}

	wake_fill_header(&e->hdr, WAKE_KIND_OPEN);
	e->ret = ctx->ret;
	e->flags = (__s32)p->flags;
	e->path_trunc = p->trunc;
	__builtin_memcpy(e->path, p->path, WAKE_PATH_LEN);

	if (bpf_ringbuf_output(&events, e, sizeof(*e), 0) != 0)
		wake_count_drop(WAKE_KIND_OPEN);

	bpf_map_delete_elem(&open_pending, &key);
	return 0;
}

/* --------------------------------------------------------------- connect */

/*
 * sock:inet_sock_set_state gives every TCP state transition, from which
 * connect attempts and their outcomes are reconstructed in userspace:
 * CLOSE→SYN_SENT is an attempt, SYN_SENT→ESTABLISHED a success, and
 * SYN_SENT→CLOSE a failure. The tracepoint has no errno, which is why the
 * outcome is derived from the transition rather than reported directly; see
 * docs/decisions/0001-connect-via-inet-sock-set-state.md.
 *
 * Note sport/dport are already in host byte order on this tracepoint.
 */
struct inet_sock_set_state_args {
	unsigned long long unused;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int wake_inet_state(struct inet_sock_set_state_args *ctx)
{
	struct wake_cfg *cfg = wake_config();
	struct wake_connect e = {};
	__u64 cgid = bpf_get_current_cgroup_id();
	char comm[WAKE_COMM_LEN];

	if (!wake_class_enabled(cfg, WAKE_KIND_CONNECT))
		return 0;
	if (ctx->protocol != IPPROTO_TCP)
		return 0;

	if (cfg->filter_port) {
		__u16 dport = ctx->dport;
		if (!bpf_map_lookup_elem(&port_filter, &dport))
			return 0;
	}

	bpf_get_current_comm(&comm, sizeof(comm));
	if (!wake_in_scope(cfg, cgid, comm))
		return 0;

	wake_fill_header(&e.hdr, WAKE_KIND_CONNECT);
	e.oldstate = ctx->oldstate;
	e.newstate = ctx->newstate;
	e.sport = ctx->sport;
	e.dport = ctx->dport;
	e.family = ctx->family;
	e.protocol = ctx->protocol;

	if (ctx->family == AF_INET6) {
		__builtin_memcpy(e.saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(e.daddr, ctx->daddr_v6, 16);
	} else {
		__builtin_memcpy(e.saddr, ctx->saddr, 4);
		__builtin_memcpy(e.daddr, ctx->daddr, 4);
	}

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0) != 0)
		wake_count_drop(WAKE_KIND_CONNECT);
	return 0;
}
