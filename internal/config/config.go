// Package config loads, validates and hashes Wake's single TOML configuration
// file (SPEC.md §4, "Config is one TOML file").
//
// Precedence is CLI flags > the config file > built-in defaults (CLAUDE.md,
// "Config precedence"). This package owns the last two layers: [Load] applies
// defaults, then the file, and returns an exported [*Config] whose fields the
// CLI layer may then overwrite directly before calling [Config.Validate]
// again. That
// direct-field-write is the "merge point for flags" other packages use;
// nothing in this package parses `os.Args`.
package config

import "time"

// Config is the effective, fully-resolved configuration for one Wake daemon
// instance. It is deliberately a plain struct with exported fields: the CLI
// layer applies flag overrides by assigning fields directly after [Load],
// then re-validates. Every field here must appear, commented, in
// deploy/wake.example.toml — see the anti-rot test in example_test.go.
type Config struct {
	Scope     Scope     `toml:"scope"`
	Classes   Classes   `toml:"classes"`
	Filters   Filters   `toml:"filters"`
	Triggers  Triggers  `toml:"triggers"`
	Ring      Ring      `toml:"ring"`
	Snapshot  Snapshot  `toml:"snapshot"`
	Redaction Redaction `toml:"redaction"`
}

// Scope is the in-kernel filter set deciding what is recorded at all
// (CONTEXT.md, "Scope"). An empty CgroupSubtree means "the whole system";
// empty allow/deny lists mean "no comm-based filtering".
type Scope struct {
	// CgroupSubtree restricts recording to processes under this cgroup path
	// (and its descendants). Empty means no cgroup restriction. Must be an
	// absolute cgroupfs-style path, e.g. "/system.slice/mstr.service".
	CgroupSubtree string `toml:"cgroup_subtree"`

	// CommAllow, if non-empty, records only processes whose comm matches one
	// of these patterns (path.Match glob syntax, e.g. "sshd*"). CommDeny
	// excludes matching comms even if CommAllow would include them; deny
	// always wins. Both are evaluated in kernel before events cross to
	// userspace (CONTEXT.md, "Scope").
	CommAllow []string `toml:"comm_allow"`
	CommDeny  []string `toml:"comm_deny"`
}

// Classes independently enables or disables each event class (CONTEXT.md,
// "Class"). Keyed by class name so that a typo ("connnect") is a validation
// error rather than a silently-ignored field.
type Classes map[string]bool

// Filters narrow file and network events further, in addition to Scope
// (CONTEXT.md, "Scope": "path prefixes, port/CIDR sets").
type Filters struct {
	// PathPrefixes restricts open events to paths starting with one of these
	// prefixes. Empty means no path restriction. Each must be absolute.
	PathPrefixes []string `toml:"path_prefixes"`

	// Ports restricts connect events to these destination ports. Each entry
	// is either a single port ("443") or an inclusive range ("8000-9000").
	// Empty means no port restriction.
	Ports []string `toml:"ports"`

	// CIDRs restricts connect events to destination addresses within one of
	// these networks (e.g. "10.0.0.0/8", "::1/128"). Empty means no address
	// restriction.
	CIDRs []string `toml:"cidrs"`
}

// Triggers holds the configuration for all five trigger types named in
// SPEC.md §2 goal 4. Each has its own cooldown to prevent snapshot storms
// (CONTEXT.md, "Trigger").
type Triggers struct {
	// WatchedProcess is a list of independent rules; a process matching any
	// rule's comm/cgroup/unit globs whose exit satisfies ExitCode fires that
	// rule's own cooldown.
	WatchedProcess []WatchedProcessTrigger `toml:"watched_process"`

	OOM        OOMTrigger        `toml:"oom"`
	Signal     SignalTrigger     `toml:"signal"`
	Manual     ManualTrigger     `toml:"manual"`
	UnitFailed UnitFailedTrigger `toml:"unit_failed"`
}

// WatchedProcessTrigger fires when a process matching its globs exits
// matching its predicate. Empty globs match anything; Name identifies the
// rule in logs, status output and the cooldown map, so it must be unique and
// non-empty.
type WatchedProcessTrigger struct {
	Name       string        `toml:"name"`
	CommGlob   string        `toml:"comm_glob"`
	CgroupGlob string        `toml:"cgroup_glob"`
	UnitGlob   string        `toml:"unit_glob"`
	ExitCode   string        `toml:"exit_code"` // see ExitCodePredicate for grammar
	Cooldown   time.Duration `toml:"cooldown"`
}

// OOMTrigger fires on any OOM kill in scope.
type OOMTrigger struct {
	Enabled  bool          `toml:"enabled"`
	Cooldown time.Duration `toml:"cooldown"`
}

// SignalTrigger fires when one of Signals is delivered to a process in
// scope. Signal names follow Go's os/signal convention without the "SIG"
// prefix stripped, e.g. "SIGSEGV", "SIGABRT".
type SignalTrigger struct {
	Enabled  bool          `toml:"enabled"`
	Signals  []string      `toml:"signals"`
	Cooldown time.Duration `toml:"cooldown"`
}

// ManualTrigger governs `wake trigger`, SIGUSR1 and the control-socket
// request (SPEC.md §2 goal 4d). It has no globs: any operator request fires
// it, subject to cooldown.
type ManualTrigger struct {
	Enabled  bool          `toml:"enabled"`
	Cooldown time.Duration `toml:"cooldown"`
}

// UnitFailedTrigger fires when a systemd unit enters the "failed" state via
// sd-bus subscription. Units, if non-empty, restricts which unit names (glob)
// are watched; empty means any unit.
type UnitFailedTrigger struct {
	Enabled  bool          `toml:"enabled"`
	Units    []string      `toml:"units"`
	Cooldown time.Duration `toml:"cooldown"`
}

// Ring bounds the in-memory event buffer by time window, event count and
// memory budget simultaneously; whichever binds first wins (CONTEXT.md,
// "Ring"). A zero value disables that particular bound, but at least one
// bound must be positive or the ring would grow forever — see Validate.
type Ring struct {
	Window            time.Duration `toml:"window"`
	MaxEvents         int           `toml:"max_events"`
	MemoryBudgetBytes int64         `toml:"memory_budget_bytes"`
}

// Snapshot configures where snapshots are written and how long they are
// kept (CONTEXT.md, "Snapshot").
type Snapshot struct {
	// Dir is the parent directory under which one subdirectory per snapshot
	// is created; must be absolute (snapshots are 0700, CLAUDE.md privacy
	// line).
	Dir string `toml:"dir"`

	// RetentionCount keeps at most this many snapshots, oldest pruned first.
	// Zero means no count-based limit.
	RetentionCount int `toml:"retention_count"`

	// RetentionBytes keeps at most this much total snapshot size, oldest
	// pruned first. Zero means no size-based limit.
	RetentionBytes int64 `toml:"retention_bytes"`

	// OnShutdown, if true, takes an implicit snapshot when the daemon stops
	// cleanly (SPEC.md §10 q6: opt-in, defaults to false).
	OnShutdown bool `toml:"on_shutdown"`
}

// Redaction configures argv/path masking applied before serialisation
// (CONTEXT.md, "Redaction"). Rule compilation lives in internal/redact; this
// struct is the config-file representation it compiles from.
type Redaction struct {
	// MaskHomeUsernames, if true, additionally masks the username segment of
	// "/home/<user>" paths (SPEC.md §4 mentions this as optional).
	MaskHomeUsernames bool `toml:"mask_home_usernames"`

	// UseDefaultRules, if true (the default), applies internal/redact's
	// built-in rules for common secrets (AWS keys, bearer tokens, password
	// flags, private key paths) in addition to Rules below.
	UseDefaultRules bool `toml:"use_default_rules"`

	Rules []RedactionRule `toml:"rules"`
}

// RedactionRule is one user-supplied masking rule.
type RedactionRule struct {
	// Name identifies the rule; it appears in the "[REDACTED:name]" marker
	// left in place of a match, so a reader knows redaction happened and
	// which rule fired.
	Name string `toml:"name"`

	// Pattern is a Go (RE2) regular expression; every match is replaced.
	Pattern string `toml:"pattern"`

	// Targets restricts which event fields this rule applies to: any of
	// "argv", "path", "filename", or "all". Empty is equivalent to "all".
	Targets []string `toml:"targets"`
}

// Default returns Wake's built-in configuration: sensible enough that a
// zero-config `wake run` works safely on a typical host (no scope
// restriction, all classes enabled, a five-minute/200k-event/128 MiB ring,
// snapshots under /var/lib/wake/snapshots, default redaction rules on,
// snapshot-on-shutdown off per SPEC.md §10 q6).
func Default() *Config {
	return &Config{
		Scope: Scope{},
		Classes: Classes{
			"exec":    true,
			"exit":    true,
			"signal":  true,
			"oom":     true,
			"open":    true,
			"connect": true,
		},
		Filters: Filters{},
		Triggers: Triggers{
			WatchedProcess: nil,
			OOM: OOMTrigger{
				Enabled:  true,
				Cooldown: 30 * time.Second,
			},
			Signal: SignalTrigger{
				Enabled:  true,
				Signals:  []string{"SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE"},
				Cooldown: 30 * time.Second,
			},
			Manual: ManualTrigger{
				Enabled:  true,
				Cooldown: 5 * time.Second,
			},
			UnitFailed: UnitFailedTrigger{
				Enabled:  true,
				Units:    nil,
				Cooldown: 30 * time.Second,
			},
		},
		Ring: Ring{
			Window:            5 * time.Minute,
			MaxEvents:         200_000,
			MemoryBudgetBytes: 128 * 1024 * 1024,
		},
		Snapshot: Snapshot{
			Dir:            "/var/lib/wake/snapshots",
			RetentionCount: 20,
			RetentionBytes: 1024 * 1024 * 1024,
			OnShutdown:     false,
		},
		Redaction: Redaction{
			MaskHomeUsernames: false,
			UseDefaultRules:   true,
			Rules:             nil,
		},
	}
}
