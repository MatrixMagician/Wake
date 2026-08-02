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

func TestApplyEnvOverridesRingAndSnapshot(t *testing.T) {
	cfg := Default()
	environ := []string{
		"WAKE_RING_WINDOW=1m",
		"WAKE_RING_MAX_EVENTS=42",
		"WAKE_SNAPSHOT_DIR=/tmp/snaps",
		"WAKE_SNAPSHOT_ON_SHUTDOWN=true",
		"UNRELATED_VAR=ignored",
		"WAKE_TRIGGERS_OOM_ENABLED=false",
	}
	if err := applyEnv(cfg, environ); err != nil {
		t.Fatalf("applyEnv: %v", err)
	}
	if cfg.Ring.Window != time.Minute {
		t.Errorf("window not overridden: %v", cfg.Ring.Window)
	}
	if cfg.Ring.MaxEvents != 42 {
		t.Errorf("max_events not overridden: %v", cfg.Ring.MaxEvents)
	}
	if cfg.Snapshot.Dir != "/tmp/snaps" {
		t.Errorf("snapshot dir not overridden: %v", cfg.Snapshot.Dir)
	}
	if !cfg.Snapshot.OnShutdown {
		t.Error("on_shutdown not overridden")
	}
	if cfg.Triggers.OOM.Enabled {
		t.Error("oom.enabled not overridden")
	}
}

func TestApplyEnvInvalidValueErrors(t *testing.T) {
	cfg := Default()
	err := applyEnv(cfg, []string{"WAKE_RING_MAX_EVENTS=not-a-number"})
	if err == nil {
		t.Fatal("expected error for invalid integer")
	}
}

func TestApplyEnvDoesNotTouchUnrelatedFields(t *testing.T) {
	cfg := Default()
	before := cfg.Triggers.Signal.Cooldown
	if err := applyEnv(cfg, nil); err != nil {
		t.Fatal(err)
	}
	if cfg.Triggers.Signal.Cooldown != before {
		t.Fatal("applyEnv with no relevant vars must not mutate config")
	}
}

// TestEnvOverridesFileWhichOverridesDefaults exercises the full precedence
// chain within this package's two layers (CLAUDE.md, "Config precedence").
func TestEnvOverridesFileWhichOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wake.toml")
	if err := os.WriteFile(path, []byte("[ring]\nmax_events = 111\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Simulate Load's two layers directly so the test doesn't depend on
	// mutating process-global os.Environ.
	cfg := Default()
	if cfg.Ring.MaxEvents == 111 {
		t.Fatal("test setup invalid: default must differ from file value")
	}
	// file layer
	fileCfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if fileCfg.Ring.MaxEvents != 111 {
		t.Fatalf("file layer not applied: %d", fileCfg.Ring.MaxEvents)
	}
	// env layer on top of file layer
	if err := applyEnv(fileCfg, []string{"WAKE_RING_MAX_EVENTS=222"}); err != nil {
		t.Fatal(err)
	}
	if fileCfg.Ring.MaxEvents != 222 {
		t.Fatalf("env layer did not win over file layer: %d", fileCfg.Ring.MaxEvents)
	}
}
