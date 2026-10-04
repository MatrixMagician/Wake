package config

import (
	"fmt"
	"net"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/MatrixMagician/wake/internal/event"
)

// Validate runs semantic checks on cfg beyond what TOML parsing already
// guarantees, and returns every problem found (not just the first) joined
// into one error, so `wake verify-config` can report a useful list in one
// pass rather than a fix-one-rerun loop.
//
// Validate is pure: it never touches the filesystem beyond checking that
// path-shaped strings look absolute, and never mutates cfg.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	c.validateScope(add)
	c.validateClasses(add)
	c.validateFilters(add)
	c.validateTriggers(add)
	c.validateRing(add)
	c.validateSnapshot(add)
	c.validateRedaction(add)

	if len(errs) == 0 {
		return nil
	}
	slices.Sort(errs)
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
}

func (c *Config) validateScope(add func(string, ...any)) {
	if c.Scope.CgroupSubtree != "" && !path.IsAbs(c.Scope.CgroupSubtree) {
		add("scope.cgroup_subtree %q must be an absolute path", c.Scope.CgroupSubtree)
	}
	for _, g := range c.Scope.CommAllow {
		if _, err := path.Match(g, ""); err != nil {
			add("scope.comm_allow glob %q does not compile: %v", g, err)
		}
	}
	for _, g := range c.Scope.CommDeny {
		if _, err := path.Match(g, ""); err != nil {
			add("scope.comm_deny glob %q does not compile: %v", g, err)
		}
	}
}

func (c *Config) validateClasses(add func(string, ...any)) {
	for name := range c.Classes {
		if !event.Class(name).Valid() || name == string(event.ClassGeneric) {
			add("classes: unknown event class %q (known: %s)", name, knownClassNames())
		}
	}
}

func knownClassNames() string {
	names := make([]string, 0, len(event.Classes))
	for _, c := range event.Classes {
		if c == event.ClassGeneric {
			continue // not independently configurable: it is the decode-total fallback
		}
		names = append(names, string(c))
	}
	return strings.Join(names, ", ")
}

func (c *Config) validateFilters(add func(string, ...any)) {
	for _, p := range c.Filters.PathPrefixes {
		if !path.IsAbs(p) {
			add("filters.path_prefixes entry %q must be an absolute path", p)
		}
	}
	for _, p := range c.Filters.Ports {
		if err := validatePortSpec(p); err != nil {
			add("filters.ports entry %q: %v", p, err)
		}
	}
	for _, cidr := range c.Filters.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("filters.cidrs entry %q is not a valid CIDR: %v", cidr, err)
		}
	}
}

// validatePortSpec accepts either a single port ("443") or an inclusive
// range ("8000-9000"), both within 1-65535 and, for a range, low <= high.
func validatePortSpec(spec string) error {
	lo, hi, isRange := strings.Cut(spec, "-")
	loN, err := strconv.Atoi(lo)
	if err != nil || loN < 1 || loN > 65535 {
		return fmt.Errorf("port %q out of range 1-65535", lo)
	}
	if !isRange {
		return nil
	}
	hiN, err := strconv.Atoi(hi)
	if err != nil || hiN < 1 || hiN > 65535 {
		return fmt.Errorf("port %q out of range 1-65535", hi)
	}
	if loN > hiN {
		return fmt.Errorf("range start %d is greater than range end %d", loN, hiN)
	}
	return nil
}

func (c *Config) validateTriggers(add func(string, ...any)) {
	seenNames := map[string]bool{}
	for i, wp := range c.Triggers.WatchedProcess {
		if wp.Name == "" {
			add("triggers.watched_process[%d]: name must not be empty", i)
		} else if seenNames[wp.Name] {
			add("triggers.watched_process[%d]: duplicate name %q", i, wp.Name)
		}
		seenNames[wp.Name] = true

		for field, glob := range map[string]string{
			"comm_glob": wp.CommGlob, "cgroup_glob": wp.CgroupGlob, "unit_glob": wp.UnitGlob,
		} {
			if glob == "" {
				continue
			}
			if _, err := path.Match(glob, ""); err != nil {
				add("triggers.watched_process[%d].%s %q does not compile: %v", i, field, glob, err)
			}
		}
		if _, err := ParseExitCodePredicate(wp.ExitCode); err != nil {
			add("triggers.watched_process[%d].exit_code %q: %v", i, wp.ExitCode, err)
		}
		if wp.Cooldown < 0 {
			add("triggers.watched_process[%d].cooldown must not be negative", i)
		}
	}

	if c.Triggers.OOM.Cooldown < 0 {
		add("triggers.oom.cooldown must not be negative")
	}

	for _, name := range c.Triggers.Signal.Signals {
		if _, err := ParseSignalName(name); err != nil {
			add("triggers.signal.signals entry %q: %v", name, err)
		}
	}
	if c.Triggers.Signal.Cooldown < 0 {
		add("triggers.signal.cooldown must not be negative")
	}

	if c.Triggers.Manual.Cooldown < 0 {
		add("triggers.manual.cooldown must not be negative")
	}

	for _, g := range c.Triggers.UnitFailed.Units {
		if _, err := path.Match(g, ""); err != nil {
			add("triggers.unit_failed.units glob %q does not compile: %v", g, err)
		}
	}
	if c.Triggers.UnitFailed.Cooldown < 0 {
		add("triggers.unit_failed.cooldown must not be negative")
	}
}

func (c *Config) validateRing(add func(string, ...any)) {
	if c.Ring.Window <= 0 && c.Ring.MaxEvents <= 0 && c.Ring.MemoryBudgetBytes <= 0 {
		add("ring: at least one of window, max_events, memory_budget_bytes must be positive, " +
			"otherwise the ring can never bind and would grow without limit")
	}
	if c.Ring.Window < 0 {
		add("ring.window must not be negative")
	}
	if c.Ring.MaxEvents < 0 {
		add("ring.max_events must not be negative")
	}
	if c.Ring.MemoryBudgetBytes < 0 {
		add("ring.memory_budget_bytes must not be negative")
	}
}

func (c *Config) validateSnapshot(add func(string, ...any)) {
	if !path.IsAbs(c.Snapshot.Dir) {
		add("snapshot.dir %q must be an absolute path", c.Snapshot.Dir)
	}
	if c.Snapshot.RetentionCount < 0 {
		add("snapshot.retention_count must not be negative")
	}
	if c.Snapshot.RetentionBytes < 0 {
		add("snapshot.retention_bytes must not be negative")
	}
}

func (c *Config) validateRedaction(add func(string, ...any)) {
	validTargets := map[string]bool{"argv": true, "path": true, "filename": true, "all": true}
	seenNames := map[string]bool{}
	for i, r := range c.Redaction.Rules {
		if r.Name == "" {
			add("redaction.rules[%d]: name must not be empty", i)
		} else if seenNames[r.Name] {
			add("redaction.rules[%d]: duplicate name %q", i, r.Name)
		}
		seenNames[r.Name] = true

		if r.Pattern == "" {
			add("redaction.rules[%d] (%s): pattern must not be empty", i, r.Name)
		} else if _, err := regexp.Compile(r.Pattern); err != nil {
			add("redaction.rules[%d] (%s): pattern %q does not compile: %v", i, r.Name, r.Pattern, err)
		}
		for _, t := range r.Targets {
			if !validTargets[t] {
				add("redaction.rules[%d] (%s): unknown target %q (want argv, path, filename, or all)",
					i, r.Name, t)
			}
		}
	}
}
