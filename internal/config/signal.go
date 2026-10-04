package config

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// ParseSignalName resolves a config-file signal name (e.g. "SIGSEGV") to its
// number, so validation and the trigger engine share one source of truth for
// "is this a real signal on this platform".
//
// The name table is x/sys/unix's, which on Linux is asm-generic/signal.h: the
// standard set plus the SIGSTKFLT/SIGPWR that Linux defines beyond POSIX. That
// this is deliberately not cross-platform is the point — signal numbers, and
// even which signals exist, differ across operating systems, and a config knob
// that silently meant something different elsewhere would be worse than one
// that does not compile there at all.
func ParseSignalName(name string) (syscall.Signal, error) {
	name = strings.ToUpper(strings.TrimSpace(name))
	if s := unix.SignalNum(name); s != 0 {
		return s, nil
	}
	return 0, fmt.Errorf("unknown signal name %q (expected e.g. SIGSEGV, SIGABRT)", name)
}
