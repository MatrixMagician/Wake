package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Load builds the effective configuration for path: defaults, then the TOML
// file at path (if it exists — a missing file is not an error, since a
// zero-config `wake run` must work per SPEC.md §9). It does not apply CLI
// flags: callers assign those directly onto the returned Config's fields
// afterwards, then call Validate again (CLAUDE.md, "Config precedence").
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

	return cfg, nil
}
