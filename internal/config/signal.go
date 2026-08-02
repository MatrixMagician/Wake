package config

import (
	"fmt"
	"strings"
	"syscall"
)

// signalsByName maps the upper-case "SIG*" name to its number on Linux. Wake
// is Linux-only (SPEC.md §3), so this is deliberately not cross-platform:
// signal numbers and even which signals exist differ across OSes, and a
// config knob that silently meant something different elsewhere would be
// worse than one that doesn't compile there at all.
//
// This list matches golang.org/x/sys/unix's Linux signal constants (in turn
// asm-generic/signal.h): the standard set plus the realtime-adjacent
// SIGSTKFLT/SIGPWR that Linux defines beyond POSIX.
var signalsByName = map[string]syscall.Signal{
	"SIGHUP": syscall.SIGHUP, "SIGINT": syscall.SIGINT, "SIGQUIT": syscall.SIGQUIT,
	"SIGILL": syscall.SIGILL, "SIGTRAP": syscall.SIGTRAP, "SIGABRT": syscall.SIGABRT,
	"SIGBUS": syscall.SIGBUS, "SIGFPE": syscall.SIGFPE, "SIGKILL": syscall.SIGKILL,
	"SIGUSR1": syscall.SIGUSR1, "SIGSEGV": syscall.SIGSEGV, "SIGUSR2": syscall.SIGUSR2,
	"SIGPIPE": syscall.SIGPIPE, "SIGALRM": syscall.SIGALRM, "SIGTERM": syscall.SIGTERM,
	"SIGSTKFLT": syscall.SIGSTKFLT, "SIGCHLD": syscall.SIGCHLD, "SIGCONT": syscall.SIGCONT,
	"SIGSTOP": syscall.SIGSTOP, "SIGTSTP": syscall.SIGTSTP, "SIGTTIN": syscall.SIGTTIN,
	"SIGTTOU": syscall.SIGTTOU, "SIGURG": syscall.SIGURG, "SIGXCPU": syscall.SIGXCPU,
	"SIGXFSZ": syscall.SIGXFSZ, "SIGVTALRM": syscall.SIGVTALRM, "SIGPROF": syscall.SIGPROF,
	"SIGWINCH": syscall.SIGWINCH, "SIGIO": syscall.SIGIO, "SIGPWR": syscall.SIGPWR,
	"SIGSYS": syscall.SIGSYS,
}

// ParseSignalName resolves a config-file signal name (e.g. "SIGSEGV") to its
// number, so validation and the trigger engine share one source of truth for
// "is this a real signal on this platform".
func ParseSignalName(name string) (syscall.Signal, error) {
	name = strings.ToUpper(strings.TrimSpace(name))
	if s, ok := signalsByName[name]; ok {
		return s, nil
	}
	return 0, fmt.Errorf("unknown signal name %q (expected e.g. SIGSEGV, SIGABRT)", name)
}
