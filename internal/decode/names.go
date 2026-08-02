package decode

import (
	"strconv"
	"strings"
	"syscall"
)

// This file turns kernel integers into the names a human reading an incident
// report needs. Every unknown value degrades to a numeric form rather than to
// an empty string: "signal 64" is useful, "" is not.

var signalNames = map[int32]string{
	1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP",
	6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1",
	11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM",
	16: "SIGSTKFLT", 17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP",
	21: "SIGTTIN", 22: "SIGTTOU", 23: "SIGURG", 24: "SIGXCPU", 25: "SIGXFSZ",
	26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH", 29: "SIGIO", 30: "SIGPWR",
	31: "SIGSYS",
}

// SignalName renders a signal number. Real-time signals are named by offset
// from SIGRTMIN, which is how operators refer to them.
func SignalName(sig int32) string {
	if n, ok := signalNames[sig]; ok {
		return n
	}
	if sig >= 34 && sig <= 64 {
		return "SIGRTMIN+" + strconv.Itoa(int(sig-34))
	}
	if sig == 0 {
		return ""
	}
	return "SIG" + strconv.Itoa(int(sig))
}

// Errno renders a positive errno value as its symbolic name, falling back to
// a numeric form for anything the platform does not name.
func Errno(n int64) string {
	if n <= 0 {
		return ""
	}
	e := syscall.Errno(n) //nolint:gosec // bounded by the kernel's own errno range
	if name := errnoNames[n]; name != "" {
		return name
	}
	if s := e.Error(); s != "" {
		return "errno " + strconv.FormatInt(n, 10) + " (" + s + ")"
	}
	return "errno " + strconv.FormatInt(n, 10)
}

var errnoNames = map[int64]string{
	1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO", 6: "ENXIO",
	7: "E2BIG", 9: "EBADF", 11: "EAGAIN", 12: "ENOMEM", 13: "EACCES",
	14: "EFAULT", 16: "EBUSY", 17: "EEXIST", 20: "ENOTDIR", 21: "EISDIR",
	22: "EINVAL", 23: "ENFILE", 24: "EMFILE", 27: "EFBIG", 28: "ENOSPC",
	30: "EROFS", 32: "EPIPE", 36: "ENAMETOOLONG", 40: "ELOOP",
	98: "EADDRINUSE", 99: "EADDRNOTAVAIL", 101: "ENETUNREACH",
	104: "ECONNRESET", 110: "ETIMEDOUT", 111: "ECONNREFUSED", 113: "EHOSTUNREACH",
}

// openFlagNames covers the flags that matter for diagnosis. The access mode
// occupies the low two bits and is handled separately, because it is a value
// rather than a set of bits.
var openFlagNames = []struct {
	bit  int32
	name string
}{
	{0o100, "O_CREAT"}, {0o200, "O_EXCL"}, {0o400, "O_NOCTTY"},
	{0o1000, "O_TRUNC"}, {0o2000, "O_APPEND"}, {0o4000, "O_NONBLOCK"},
	{0o10000, "O_DSYNC"}, {0o40000, "O_DIRECT"}, {0o100000, "O_LARGEFILE"},
	{0o200000, "O_DIRECTORY"}, {0o400000, "O_NOFOLLOW"}, {0o1000000, "O_NOATIME"},
	{0o2000000, "O_CLOEXEC"}, {0o4010000, "O_SYNC"}, {0o20200000, "O_PATH"},
}

// OpenFlags renders openat flags in the pipe-separated form strace uses, so
// that the output is greppable by anyone who has ever read an strace log.
func OpenFlags(flags int32) string {
	var parts []string
	switch flags & 0o3 {
	case 0:
		parts = append(parts, "O_RDONLY")
	case 1:
		parts = append(parts, "O_WRONLY")
	case 2:
		parts = append(parts, "O_RDWR")
	default:
		parts = append(parts, "O_ACCMODE_3")
	}
	for _, f := range openFlagNames {
		if flags&f.bit == f.bit {
			parts = append(parts, f.name)
		}
	}
	return strings.Join(parts, "|")
}

// TCP states, from include/net/tcp_states.h, as reported by
// sock:inet_sock_set_state.
const (
	tcpEstablished int32 = 1
	tcpSynSent     int32 = 2
	tcpSynRecv     int32 = 3
	tcpFinWait1    int32 = 4
	tcpFinWait2    int32 = 5
	tcpTimeWait    int32 = 6
	tcpClose       int32 = 7
	tcpCloseWait   int32 = 8
	tcpLastAck     int32 = 9
	tcpListen      int32 = 10
	tcpClosing     int32 = 11
	tcpNewSynRecv  int32 = 12
)

var tcpStateNames = map[int32]string{
	tcpEstablished: "TCP_ESTABLISHED", tcpSynSent: "TCP_SYN_SENT",
	tcpSynRecv: "TCP_SYN_RECV", tcpFinWait1: "TCP_FIN_WAIT1",
	tcpFinWait2: "TCP_FIN_WAIT2", tcpTimeWait: "TCP_TIME_WAIT",
	tcpClose: "TCP_CLOSE", tcpCloseWait: "TCP_CLOSE_WAIT",
	tcpLastAck: "TCP_LAST_ACK", tcpListen: "TCP_LISTEN",
	tcpClosing: "TCP_CLOSING", tcpNewSynRecv: "TCP_NEW_SYN_RECV",
}

// TCPState renders a TCP state number using the kernel's own names.
func TCPState(s int32) string {
	if n, ok := tcpStateNames[s]; ok {
		return n
	}
	return "TCP_STATE_" + strconv.Itoa(int(s))
}

// Protocol renders an IP protocol number for the protocols this tracepoint
// can report.
func Protocol(p uint16) string {
	switch p {
	case 6:
		return "tcp"
	case 132:
		return "sctp"
	case 262:
		return "mptcp"
	default:
		return "proto " + strconv.Itoa(int(p))
	}
}
