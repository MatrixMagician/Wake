/* SPDX-License-Identifier: Apache-2.0 */
/*
 * wake_event.h — the wire contract between Wake's BPF programs and its Go
 * decoder. Both sides must agree exactly; internal/decode/wire.go mirrors this
 * layout field for field and there is a test asserting the sizes match.
 *
 * Layout rules:
 *  - Fixed-size, naturally aligned, little-endian (x86_64/aarch64 only).
 *  - Variable-length data (argv, path) is a fixed-capacity tail with an
 *    explicit length, never a pointer. Truncation is flagged, never silent.
 *  - Every record starts with the same header so the decoder can route an
 *    unknown kind to the generic path instead of misreading it.
 */
#ifndef WAKE_EVENT_H
#define WAKE_EVENT_H

#define WAKE_WIRE_VERSION 1

/* Kernel-side sizing budgets. Kept small: the BPF stack is 512 bytes, so
 * anything larger is assembled in a per-CPU scratch map. */
#define WAKE_COMM_LEN 16
#define WAKE_ARGV_LEN 512 /* total bytes of NUL-separated argv, truncated */
#define WAKE_PATH_LEN 256 /* truncated openat path */
#define WAKE_ARGV_MAX 20  /* maximum argv entries read */

enum wake_kind {
	WAKE_KIND_EXEC = 1,
	WAKE_KIND_EXIT = 2,
	WAKE_KIND_SIGNAL = 3,
	WAKE_KIND_OOM = 4,
	WAKE_KIND_OPEN = 5,
	WAKE_KIND_CONNECT = 6,
};

/* Per-class drop counters live in a BPF array map indexed by wake_kind, so a
 * kernel-side reserve failure is countable rather than invisible. */
#define WAKE_DROP_SLOTS 8

struct wake_header {
	__u64 ts_ns;      /* bpf_ktime_get_boot_ns(), converted to wall clock in Go */
	__u32 kind;       /* enum wake_kind */
	__u32 wire_ver;   /* WAKE_WIRE_VERSION */
	__u32 pid;        /* tgid */
	__u32 tid;        /* pid */
	__u32 uid;
	__u32 _pad;
	__u64 cgroup_id;
	char comm[WAKE_COMM_LEN];
};

/* sched:sched_process_exec
 * Verified against /sys/kernel/tracing/events/sched/sched_process_exec/format
 * on 7.1.5-201.fc44.x86_64: __data_loc char[] filename @8, pid @12, old_pid @16.
 * argv is read from the new mm's arg_start/arg_end via BTF, not from the
 * tracepoint, because the tracepoint does not carry it. */
struct wake_exec {
	struct wake_header hdr;
	__u32 ppid;
	__u32 argv_len;   /* bytes used in argv */
	__u8 argv_trunc;  /* 1 if argv was cut short */
	__u8 _pad[3];
	char filename[WAKE_PATH_LEN];
	char argv[WAKE_ARGV_LEN]; /* NUL-separated */
};

/* sched:sched_process_exit — comm[16] @8, pid @24, prio @28, group_dead @32.
 * Exit code/signal come from task->exit_code via CO-RE, as the tracepoint does
 * not expose them: low 7 bits are the terminating signal, high 8 bits the
 * exit status (see include/linux/sched.h). */
struct wake_exit {
	struct wake_header hdr;
	__s32 exit_code;
	__s32 exit_signal;
	__u8 group_dead;
	__u8 _pad[7];
};

/* signal:signal_deliver — sig @8, errno @12, code @16, sa_handler @24,
 * sa_flags @32. The signal is observed at delivery, so hdr.pid is the target;
 * the sender is recovered from the current task where available. */
struct wake_signal {
	struct wake_header hdr;
	__s32 sig;
	__s32 code;
	__u32 sender_pid;
	__u32 _pad;
};

/* oom:mark_victim — pid @8, __data_loc comm @12, total_vm @16, anon_rss @24,
 * file_rss @32, shmem_rss @40, uid @48, pgtables @56, oom_score_adj @64.
 * Sizes are in kB, as the tracepoint's print format documents. */
struct wake_oom {
	struct wake_header hdr;
	__u64 total_vm_kb;
	__u64 anon_rss_kb;
	__u64 file_rss_kb;
	__u64 shmem_rss_kb;
	__s16 oom_score_adj;
	__u8 _pad[6];
};

/* syscalls:sys_enter_openat (dfd @16, filename ptr @24, flags @32, mode @40)
 * paired with syscalls:sys_exit_openat (ret @16) via a per-task scratch map,
 * so that both successful and failing opens carry their errno. Only the path,
 * flags and result are captured — never file contents. */
struct wake_open {
	struct wake_header hdr;
	__s64 ret;
	__s32 flags;
	__u8 path_trunc;
	__u8 _pad[3];
	char path[WAKE_PATH_LEN];
};

/* sock:inet_sock_set_state — skaddr @8, oldstate @16, newstate @20, sport @24,
 * dport @26, family @28, protocol @30, saddr @32, daddr @36, saddr_v6 @40,
 * daddr_v6 @56. Note sport/dport are already host byte order in this
 * tracepoint, unlike most socket paths. */
struct wake_connect {
	struct wake_header hdr;
	__s32 oldstate;
	__s32 newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[16];
	__u8 daddr[16];
};

#endif /* WAKE_EVENT_H */
