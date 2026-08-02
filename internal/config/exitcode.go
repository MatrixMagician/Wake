package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ExitCodePredicate is a compiled watched-process exit predicate: the
// trigger engine calls Match with the process's actual exit outcome to
// decide whether a WatchedProcessTrigger rule fires.
//
// Grammar (config field triggers.watched_process[].exit_code):
//
//	""        - matches any exit (equivalent to "any")
//	"any"     - matches any exit
//	"signal"  - matches only exits caused by an uncaught signal
//	"nonzero" - matches any non-zero exit code, or death by signal
//	"N"       - matches exactly exit code N (e.g. "137")
//	">N", ">=N", "<N", "<=N" - matches exit codes compared to N;
//	            never matches a death-by-signal exit, since there is no code
//	            to compare
//
// This is deliberately small: it is a filter on "how did the process die",
// not a general expression language.
type ExitCodePredicate struct {
	kind string // "any", "signal", "nonzero", "eq", "gt", "ge", "lt", "le"
	n    int32
}

// Match reports whether an exit with the given code (meaningless if
// bySignal is true) and signal-death flag satisfies p.
func (p ExitCodePredicate) Match(code int32, bySignal bool) bool {
	switch p.kind {
	case "any":
		return true
	case "signal":
		return bySignal
	case "nonzero":
		return bySignal || code != 0
	case "eq":
		return !bySignal && code == p.n
	case "gt":
		return !bySignal && code > p.n
	case "ge":
		return !bySignal && code >= p.n
	case "lt":
		return !bySignal && code < p.n
	case "le":
		return !bySignal && code <= p.n
	default:
		return false // unreachable given ParseExitCodePredicate validates kind
	}
}

// ParseExitCodePredicate compiles a config-file exit-code predicate string.
// See ExitCodePredicate for the grammar.
func ParseExitCodePredicate(s string) (ExitCodePredicate, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "", "any":
		return ExitCodePredicate{kind: "any"}, nil
	case "signal":
		return ExitCodePredicate{kind: "signal"}, nil
	case "nonzero":
		return ExitCodePredicate{kind: "nonzero"}, nil
	}

	kind := "eq"
	rest := s
	switch {
	case strings.HasPrefix(s, ">="):
		kind, rest = "ge", s[2:]
	case strings.HasPrefix(s, "<="):
		kind, rest = "le", s[2:]
	case strings.HasPrefix(s, ">"):
		kind, rest = "gt", s[1:]
	case strings.HasPrefix(s, "<"):
		kind, rest = "lt", s[1:]
	}

	n, err := strconv.ParseInt(rest, 10, 32)
	if err != nil {
		return ExitCodePredicate{}, fmt.Errorf(
			"invalid exit-code predicate %q (want \"\", \"any\", \"signal\", \"nonzero\", "+
				"an integer, or a comparison like \">0\"): %w", s, err)
	}
	return ExitCodePredicate{kind: kind, n: int32(n)}, nil
}
