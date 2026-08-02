package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Load builds the effective configuration for path: defaults, then the TOML
// file at path (if it exists — a missing file is not an error, since a
// zero-config `wake run` must work per SPEC.md §8), then WAKE_* environment
// overrides. It does not apply CLI flags: callers assign those directly onto
// the returned Config's fields afterwards, then call Validate again
// (CLAUDE.md, "Config precedence").
//
// Load does not validate; callers must call Config.Validate before using the
// result, so that `wake verify-config` and `wake run` share one code path
// from raw bytes to a pass/fail verdict.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		if _, err := os.Stat(path); err == nil {
			meta, err := toml.DecodeFile(path, cfg)
			if err != nil {
				return nil, fmt.Errorf("parsing config file %s: %w", path, err)
			}
			if undecoded := meta.Undecoded(); len(undecoded) > 0 {
				return nil, fmt.Errorf("config file %s: unknown key %q", path, undecoded[0].String())
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("reading config file %s: %w", path, err)
		}
	}

	if err := applyEnv(cfg, os.Environ()); err != nil {
		return nil, err
	}

	return cfg, nil
}

// envPrefix is the namespace for environment-variable overrides
// (CLAUDE.md, "Config precedence": "CLI flags > WAKE_* env > file >
// defaults").
const envPrefix = "WAKE_"

// applyEnv applies WAKE_* environment overrides on top of cfg, which must
// already hold file-or-default values. Only a deliberately small, documented
// set of scalar knobs is exposed this way — the ones an operator plausibly
// wants to flip per-invocation without editing the file (ring bounds,
// snapshot directory, on-shutdown flag, and the global enable/disable
// switches for scope and each trigger). Structured settings (rules, globs,
// per-trigger cooldowns) are file-only: env vars are not a serialisation
// format.
//
// environ is passed in explicitly (rather than read via os.Environ inside)
// so that tests can exercise this deterministically without mutating global
// process state.
func applyEnv(cfg *Config, environ []string) error {
	env := make(map[string]string, len(environ))
	for _, kv := range environ {
		if !strings.HasPrefix(kv, envPrefix) {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		env[k] = v
	}

	type binding struct {
		key   string
		apply func(string) error
	}
	bindings := []binding{
		{"WAKE_SCOPE_CGROUP_SUBTREE", func(v string) error { cfg.Scope.CgroupSubtree = v; return nil }},
		{"WAKE_RING_WINDOW", durationSetter(&cfg.Ring.Window)},
		{"WAKE_RING_MAX_EVENTS", intSetter(&cfg.Ring.MaxEvents)},
		{"WAKE_RING_MEMORY_BUDGET_BYTES", int64Setter(&cfg.Ring.MemoryBudgetBytes)},
		{"WAKE_SNAPSHOT_DIR", func(v string) error { cfg.Snapshot.Dir = v; return nil }},
		{"WAKE_SNAPSHOT_RETENTION_COUNT", intSetter(&cfg.Snapshot.RetentionCount)},
		{"WAKE_SNAPSHOT_RETENTION_BYTES", int64Setter(&cfg.Snapshot.RetentionBytes)},
		{"WAKE_SNAPSHOT_ON_SHUTDOWN", boolSetter(&cfg.Snapshot.OnShutdown)},
		{"WAKE_TRIGGERS_OOM_ENABLED", boolSetter(&cfg.Triggers.OOM.Enabled)},
		{"WAKE_TRIGGERS_SIGNAL_ENABLED", boolSetter(&cfg.Triggers.Signal.Enabled)},
		{"WAKE_TRIGGERS_MANUAL_ENABLED", boolSetter(&cfg.Triggers.Manual.Enabled)},
		{"WAKE_TRIGGERS_UNIT_FAILED_ENABLED", boolSetter(&cfg.Triggers.UnitFailed.Enabled)},
	}

	for _, b := range bindings {
		v, ok := env[b.key]
		if !ok {
			continue
		}
		if err := b.apply(v); err != nil {
			return fmt.Errorf("environment variable %s=%q: %w", b.key, v, err)
		}
	}
	return nil
}

func durationSetter(dst *time.Duration) func(string) error {
	return func(v string) error {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		*dst = d
		return nil
	}
}

func intSetter(dst *int) func(string) error {
	return func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid integer: %w", err)
		}
		*dst = n
		return nil
	}
}

func int64Setter(dst *int64) func(string) error {
	return func(v string) error {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer: %w", err)
		}
		*dst = n
		return nil
	}
}

func boolSetter(dst *bool) func(string) error {
	return func(v string) error {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid boolean: %w", err)
		}
		*dst = b
		return nil
	}
}
