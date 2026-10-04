package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	if cfg.Hash() != Default().Hash() {
		t.Fatal("missing config file should produce the same config as Default()")
	}
}

func TestLoadEmptyPathReturnsDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Hash() != Default().Hash() {
		t.Fatal("Load(\"\") should produce the same config as Default()")
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wake.toml")
	toml := `
[scope]
cgroup_subtree = "/system.slice/mstr.service"

[ring]
window = "10m"
max_events = 5000
memory_budget_bytes = 1048576
`
	if err := os.WriteFile(path, []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scope.CgroupSubtree != "/system.slice/mstr.service" {
		t.Errorf("cgroup_subtree not applied: %+v", cfg.Scope)
	}
	if cfg.Ring.Window != 10*time.Minute || cfg.Ring.MaxEvents != 5000 {
		t.Errorf("ring not overridden: %+v", cfg.Ring)
	}
	// Untouched sections keep their defaults.
	if !cfg.Classes["exec"] {
		t.Errorf("classes should retain default when file doesn't mention it: %+v", cfg.Classes)
	}
}

func TestLoadUnknownKeyRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wake.toml")
	toml := "[ring]\nmax_evnts = 5\n" // typo
	if err := os.WriteFile(path, []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestLoadMalformedTOMLRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wake.toml")
	if err := os.WriteFile(path, []byte("this is not [ valid toml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected parse error")
	}
}
