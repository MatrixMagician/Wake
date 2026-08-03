// Package doctor answers one question: will Wake work on this host, and if
// not, precisely why?
//
// The design rule here is that a failed check must name the remedy. "BTF not
// available" is a diagnosis; "BTF not available — this kernel was built
// without CONFIG_DEBUG_INFO_BTF, so Wake cannot run; Fedora ships BTF, RHEL
// does from 8.2" is help. Every check below carries its own explanation
// because the person running `wake doctor` is usually already having a bad
// day.
package doctor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Result is the outcome of one check.
type Result struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Fatal  bool   `json:"fatal"`            // a failure here means Wake cannot run at all
	Detail string `json:"detail"`           // what was observed
	Remedy string `json:"remedy,omitempty"` // what to do about it
}

// Report is the full preflight.
type Report struct {
	Results []Result `json:"results"`
}

// OK reports whether every fatal check passed.
func (r Report) OK() bool {
	for _, c := range r.Results {
		if c.Fatal && !c.OK {
			return false
		}
	}
	return true
}

// Run performs every check. It never returns an error: the report *is* the
// result, and a check that cannot run is itself a finding.
func Run() Report {
	return Report{Results: []Result{
		checkKernelVersion(),
		checkBTF(),
		checkRingbuf(),
		checkTracepoints(),
		checkCapabilities(),
		checkMemlock(),
		checkUnprivilegedBPFSetting(),
		checkSELinux(),
		checkSnapshotDir(),
		checkProcFDReadlink(),
	}}
}

// checkProcFDReadlink catches a failure that is invisible until you read a
// snapshot: readlink() on /proc/<pid>/fd/* is gated on PTRACE_MODE_READ, not
// on file permissions, so without CAP_SYS_PTRACE the fd listing in every
// snapshot is written successfully and is entirely blank. It is not fatal --
// the ring history is the point of a snapshot and is unaffected -- but it
// silently removes half of the proc scrape's value, so it is worth a warning.
func checkProcFDReadlink() Result {
	const name = "proc fd listing"

	pid, ok := foreignPID()
	if !ok {
		// Nothing owned by another user to test against (a container, most
		// likely). Saying so is more honest than reporting a pass.
		return Result{
			Name: name, OK: true,
			Detail: "not checked: no process owned by another user to test against",
		}
	}

	if _, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/1", pid)); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return Result{
				Name: name, OK: false, Fatal: false,
				Detail: fmt.Sprintf("cannot read fd targets of pid %d owned by another user", pid),
				Remedy: "Grant CAP_SYS_PTRACE. Snapshots will still be written and the " +
					"ring history is unaffected, but every fd in proc/fd_listing.txt " +
					"will read [permission denied] instead of its target. The shipped " +
					"unit at deploy/wake.service grants it.",
			}
		}
		// The process exited between choosing it and reading it, or some
		// other transient. Not evidence of anything.
		return Result{Name: name, OK: true, Detail: "not checked: " + err.Error()}
	}

	return Result{Name: name, OK: true, Detail: "fd targets readable across users"}
}

// foreignPID returns a live pid owned by a different uid, which is the only
// case that exercises the ptrace gate: a process's own fds are always
// readable regardless of capabilities.
func foreignPID() (int, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	self := os.Geteuid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) == self {
			continue
		}
		return pid, true
	}
	return 0, false
}

func checkKernelVersion() Result {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return Result{Name: "kernel version", Fatal: false,
			Detail: fmt.Sprintf("uname failed: %v", err)}
	}
	rel := nulString(u.Release[:])
	return Result{Name: "kernel version", OK: true, Detail: rel}
}

// checkBTF is the one hard prerequisite. Wake has no fallback compilation
// path by design (SPEC.md §2, non-goals), so no BTF means no Wake.
func checkBTF() Result {
	const path = "/sys/kernel/btf/vmlinux"
	if _, err := os.Stat(path); err != nil {
		return Result{
			Name: "kernel BTF", Fatal: true,
			Detail: fmt.Sprintf("%s is not present: %v", path, err),
			Remedy: "This kernel was built without CONFIG_DEBUG_INFO_BTF. Wake requires " +
				"BTF for CO-RE and ships no fallback compilation path. Fedora and " +
				"RHEL ≥ 8.2 kernels have it; a custom or very old kernel may not.",
		}
	}
	return Result{Name: "kernel BTF", OK: true, Detail: path + " present"}
}

// checkRingbuf reports whether BPF_MAP_TYPE_RINGBUF exists, which it does from
// 5.8. Wake uses ring buffers rather than perf buffers, so this is fatal.
func checkRingbuf() Result {
	rel := kernelRelease()
	major, minor := parseRelease(rel)
	if major > 5 || (major == 5 && minor >= 8) {
		return Result{Name: "BPF ring buffer", OK: true,
			Detail: fmt.Sprintf("kernel %s supports BPF_MAP_TYPE_RINGBUF", rel)}
	}
	return Result{
		Name: "BPF ring buffer", Fatal: true,
		Detail: fmt.Sprintf("kernel %s predates BPF_MAP_TYPE_RINGBUF (5.8)", rel),
		Remedy: "Wake uses ring buffers rather than perf buffers so that drops are " +
			"countable. Upgrade to 5.8 or newer.",
	}
}

// tracepoints lists what Wake binds, with the class each one serves, so that a
// missing hook names the capability that is lost rather than just a path.
var tracepoints = []struct{ path, class string }{
	{"/sys/kernel/tracing/events/sched/sched_process_exec", "exec"},
	{"/sys/kernel/tracing/events/sched/sched_process_exit", "exit"},
	{"/sys/kernel/tracing/events/signal/signal_deliver", "signal"},
	{"/sys/kernel/tracing/events/oom/mark_victim", "oom"},
	{"/sys/kernel/tracing/events/syscalls/sys_enter_openat", "open"},
	{"/sys/kernel/tracing/events/syscalls/sys_exit_openat", "open"},
	{"/sys/kernel/tracing/events/sock/inet_sock_set_state", "connect"},
}

func checkTracepoints() Result {
	var missing []string
	for _, tp := range tracepoints {
		if _, err := os.Stat(filepath.Join(tp.path, "format")); err != nil {
			missing = append(missing, fmt.Sprintf("%s (class %q)",
				strings.TrimPrefix(tp.path, "/sys/kernel/tracing/events/"), tp.class))
		}
	}
	if len(missing) == 0 {
		return Result{Name: "tracepoints", OK: true,
			Detail: fmt.Sprintf("all %d tracepoints present", len(tracepoints))}
	}
	// Not fatal: a host missing one tracepoint can still run every other
	// class, and refusing to start would be a worse answer than degrading.
	return Result{
		Name: "tracepoints", OK: false, Fatal: false,
		Detail: "missing: " + strings.Join(missing, ", "),
		Remedy: "Disable the affected classes in wake.toml, or check that tracefs is " +
			"mounted (mount -t tracefs none /sys/kernel/tracing). Reading the " +
			"format files needs root.",
	}
}

func checkCapabilities() Result {
	if os.Geteuid() == 0 {
		return Result{Name: "privileges", OK: true, Detail: "running as root"}
	}
	// Reading the effective capability set is the honest check, but the
	// simple and reliable signal is whether we can actually load a program.
	// Report what we know and point at the unit file, which is where this is
	// normally solved.
	return Result{
		Name: "privileges", OK: false, Fatal: true,
		Detail: fmt.Sprintf("running as uid %d, not root", os.Geteuid()),
		Remedy: "Wake needs CAP_BPF, CAP_PERFMON and CAP_SYS_RESOURCE (plus " +
			"CAP_DAC_READ_SEARCH for /proc scrapes), or root. The shipped unit at " +
			"deploy/wake.service grants exactly these.",
	}
}

func checkMemlock() Result {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return Result{Name: "memlock rlimit", Detail: fmt.Sprintf("getrlimit failed: %v", err)}
	}
	if lim.Cur == unix.RLIM_INFINITY {
		return Result{Name: "memlock rlimit", OK: true, Detail: "unlimited"}
	}
	// Wake raises this itself at load time given CAP_SYS_RESOURCE, so a low
	// limit is only a problem when that capability is absent.
	return Result{
		Name: "memlock rlimit", OK: true,
		Detail: fmt.Sprintf("%d bytes; Wake raises this at load time given CAP_SYS_RESOURCE", lim.Cur),
	}
}

// checkUnprivilegedBPFSetting exists to head off a red herring. Operators
// frequently blame kernel.unprivileged_bpf_disabled for a failed load; it is
// irrelevant when Wake holds CAP_BPF, and saying so saves an hour.
func checkUnprivilegedBPFSetting() Result {
	b, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled")
	if err != nil {
		return Result{Name: "unprivileged_bpf_disabled", OK: true,
			Detail: "not readable; not relevant to a privileged Wake"}
	}
	return Result{
		Name: "unprivileged_bpf_disabled", OK: true,
		Detail: fmt.Sprintf("= %s (irrelevant: Wake runs with CAP_BPF or as root, "+
			"so this setting does not apply to it)", strings.TrimSpace(string(b))),
	}
}

func checkSELinux() Result {
	b, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return Result{Name: "SELinux", OK: true, Detail: "not enabled"}
	}
	mode := strings.TrimSpace(string(b))
	if mode != "1" {
		return Result{Name: "SELinux", OK: true, Detail: "permissive or disabled"}
	}
	return Result{
		Name: "SELinux", OK: true,
		Detail: "enforcing",
		Remedy: "If loading fails with EACCES despite holding the capabilities, check " +
			"for denials with `ausearch -m avc -ts recent`; bpf and perfmon classes " +
			"are the ones to look for.",
	}
}

func checkSnapshotDir() Result {
	const dir = "/var/lib/wake/snapshots"
	fi, err := os.Stat(dir)
	if err != nil {
		return Result{
			Name: "snapshot directory", OK: false, Fatal: false,
			Detail: fmt.Sprintf("%s does not exist: %v", dir, err),
			Remedy: "Wake creates it on first snapshot. Under a hardened unit with " +
				"ProtectSystem=strict it must be listed in ReadWritePaths, or " +
				"provided by StateDirectory=wake.",
		}
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		return Result{
			Name: "snapshot directory", OK: false, Fatal: false,
			Detail: fmt.Sprintf("%s is mode %o, not 700", dir, perm),
			Remedy: "Snapshots contain other people's command lines and file paths. " +
				"Run: chmod 700 " + dir,
		}
	}
	return Result{Name: "snapshot directory", OK: true, Detail: dir + " present, mode 700"}
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return nulString(u.Release[:])
}

func parseRelease(rel string) (major, minor int) {
	_, _ = fmt.Sscanf(rel, "%d.%d", &major, &minor)
	return
}

func nulString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
