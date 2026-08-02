// Package redact masks secrets in argv and paths before an [event.Event] is
// serialised. Redaction is applied in place, in userspace, before any bytes
// reach a snapshot file or a `wake watch` client — never after (CONTEXT.md,
// "Redaction"; CLAUDE.md's hard privacy line: "Redaction of argv/paths
// happens before serialisation").
//
// Rules are compiled once from [config.Redaction] and reused for every
// event; matching is therefore just running a handful of precompiled RE2
// regular expressions per event, cheap enough for the hot path.
package redact

import (
	"fmt"
	"regexp"

	"github.com/MatrixMagician/wake/internal/config"
	"github.com/MatrixMagician/wake/internal/event"
)

// target is a bitmask of the event fields one rule applies to.
type target uint8

const (
	targetArgv target = 1 << iota
	targetPath
	targetFilename
	targetAll = targetArgv | targetPath | targetFilename
)

func parseTargets(names []string) (target, error) {
	if len(names) == 0 {
		return targetAll, nil
	}
	var t target
	for _, n := range names {
		switch n {
		case "argv":
			t |= targetArgv
		case "path":
			t |= targetPath
		case "filename":
			t |= targetFilename
		case "all":
			t |= targetAll
		default:
			return 0, fmt.Errorf("unknown redaction target %q (want argv, path, filename, or all)", n)
		}
	}
	return t, nil
}

// rule is one compiled masking rule: every match of re, in a field selected
// by targets, is replaced with "[REDACTED:name]".
type rule struct {
	name    string
	re      *regexp.Regexp
	targets target
}

// flagValueRule matches an argv entry that is a bare flag name expected to
// be followed by its value in the *next* argv entry (e.g. "-p" "hunter2"),
// a shape a single per-entry regex cannot catch because the secret and the
// thing that identifies it as a secret are in different argv slots.
type flagValueRule struct {
	name   string
	flagRe *regexp.Regexp
}

// Redactor holds every compiled rule for one configuration. The zero value
// is not usable; construct with [New]. A nil *Redactor is safe to call
// Redact on and is a no-op, so callers that construct a Redactor once at
// startup do not need a separate "redaction disabled" branch.
type Redactor struct {
	rules     []rule
	flagRules []flagValueRule
	maskHome  bool
}

// New compiles a Redactor from cfg. Pattern compile errors are reported with
// the offending rule's name; callers are expected to have already run
// [config.Config.Validate], which checks pattern compilation as part of
// semantic validation, so a New failure here should not occur on a
// validated config — New re-checks anyway because a Redactor must never be
// silently partial.
func New(cfg config.Redaction) (*Redactor, error) {
	r := &Redactor{maskHome: cfg.MaskHomeUsernames}

	for _, rc := range cfg.Rules {
		compiled, err := compileRule(rc)
		if err != nil {
			return nil, err
		}
		if compiled != nil {
			r.rules = append(r.rules, *compiled)
		}
	}

	if cfg.UseDefaultRules {
		r.rules = append(r.rules, defaultRules()...)
		r.flagRules = append(r.flagRules, defaultFlagValueRules()...)
	}

	return r, nil
}

// compileRule compiles one config-file rule. An empty pattern is treated as
// a deliberate no-op (compileRule returns nil, nil) rather than compiled
// into an always-matching regexp: an empty RE2 pattern matches the empty
// string at every position, which would shred every field into
// per-character markers without masking anything real. config.Validate
// already rejects empty patterns for rules meant to take effect; this is
// belt-and-braces for callers that bypass validation.
func compileRule(rc config.RedactionRule) (*rule, error) {
	if rc.Pattern == "" {
		return nil, nil
	}
	re, err := regexp.Compile(rc.Pattern)
	if err != nil {
		return nil, fmt.Errorf("redaction rule %q: pattern %q does not compile: %w", rc.Name, rc.Pattern, err)
	}
	t, err := parseTargets(rc.Targets)
	if err != nil {
		return nil, fmt.Errorf("redaction rule %q: %w", rc.Name, err)
	}
	return &rule{name: rc.Name, re: re, targets: t}, nil
}

// Redact masks e's argv, path and filename fields in place according to r's
// rules. Calling Redact on a nil *Redactor is a safe no-op.
func (r *Redactor) Redact(e *event.Event) {
	if r == nil || e == nil {
		return
	}
	e.Argv = r.redactArgv(e.Argv)
	e.Path = r.redactField(e.Path, targetPath)
	e.Filename = r.redactField(e.Filename, targetFilename)
}

// redactField applies every rule whose targets include t to s in order, and
// (for path fields only) home-username masking.
func (r *Redactor) redactField(s string, t target) string {
	if s == "" {
		return s
	}
	for _, rl := range r.rules {
		if rl.targets&t == 0 {
			continue
		}
		s = rl.re.ReplaceAllString(s, "[REDACTED:"+rl.name+"]")
	}
	if t == targetPath && r.maskHome {
		s = homeUsernameRe.ReplaceAllString(s, "[REDACTED:home-username]")
	}
	return s
}

// redactArgv masks each argv entry, additionally handling the case where a
// secret's value sits in the argv entry *after* the flag that names it
// (e.g. ["-p", "hunter2"]): the entry following a recognised bare flag is
// replaced wholesale, since by definition its content is the secret, not
// something a content-matching regex needs to locate.
func (r *Redactor) redactArgv(argv []string) []string {
	if len(argv) == 0 {
		return argv
	}
	out := make([]string, len(argv))
	copy(out, argv)

	redactNextAs := "" // rule name to attribute the *next* entry's redaction to
	for i, a := range argv {
		if redactNextAs != "" {
			out[i] = "[REDACTED:" + redactNextAs + "]"
			redactNextAs = ""
			continue
		}
		for _, fr := range r.flagRules {
			if fr.flagRe.MatchString(a) {
				redactNextAs = fr.name
				break
			}
		}
		out[i] = r.redactField(a, targetArgv)
	}
	return out
}
