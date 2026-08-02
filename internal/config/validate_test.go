package config

import (
	"strings"
	"testing"
)

func TestDefaultValidates(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() must validate cleanly: %v", err)
	}
}

func TestDefaultIsZeroConfigSafe(t *testing.T) {
	cfg := Default()
	if cfg.Ring.Window <= 0 && cfg.Ring.MaxEvents <= 0 && cfg.Ring.MemoryBudgetBytes <= 0 {
		t.Fatal("default ring has no bound that can ever bind")
	}
	if cfg.Snapshot.Dir == "" {
		t.Fatal("default snapshot dir must be set")
	}
}

func TestValidateUnknownEventClass(t *testing.T) {
	cfg := Default()
	cfg.Classes["connnect"] = true // typo
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown event class") {
		t.Fatalf("expected unknown event class error, got %v", err)
	}
}

func TestValidateGenericClassRejected(t *testing.T) {
	cfg := Default()
	cfg.Classes["generic"] = true
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown event class") {
		t.Fatalf("expected generic class to be rejected as not independently configurable, got %v", err)
	}
}

func TestValidateMalformedCIDR(t *testing.T) {
	cfg := Default()
	cfg.Filters.CIDRs = []string{"10.0.0.0/40"}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "not a valid CIDR") {
		t.Fatalf("expected CIDR error, got %v", err)
	}
}

func TestValidatePortOutOfRange(t *testing.T) {
	cases := []string{"0", "70000", "100-99", "abc", "1-70000"}
	for _, p := range cases {
		cfg := Default()
		cfg.Filters.Ports = []string{p}
		if err := cfg.Validate(); err == nil {
			t.Errorf("port spec %q: expected validation error, got nil", p)
		}
	}
	cfg := Default()
	cfg.Filters.Ports = []string{"443", "8000-9000"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid port specs rejected: %v", err)
	}
}

func TestValidateBadRegex(t *testing.T) {
	cfg := Default()
	cfg.Redaction.Rules = []RedactionRule{{Name: "bad", Pattern: "["}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "does not compile") {
		t.Fatalf("expected regex compile error, got %v", err)
	}
}

func TestValidateCooldownNegative(t *testing.T) {
	cfg := Default()
	cfg.Triggers.OOM.Cooldown = -1
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("expected negative cooldown error, got %v", err)
	}
}

func TestValidateRingNeverBinds(t *testing.T) {
	cfg := Default()
	cfg.Ring.Window = 0
	cfg.Ring.MaxEvents = 0
	cfg.Ring.MemoryBudgetBytes = 0
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "can never bind") {
		t.Fatalf("expected ring-never-binds error, got %v", err)
	}
}

func TestValidateSnapshotDirNotAbsolute(t *testing.T) {
	cfg := Default()
	cfg.Snapshot.Dir = "relative/path"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be an absolute path") {
		t.Fatalf("expected absolute-path error, got %v", err)
	}
}

func TestValidateGlobCannotCompile(t *testing.T) {
	cfg := Default()
	// path.Match returns ErrBadPattern for an unterminated character class.
	cfg.Scope.CommAllow = []string{"["}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "does not compile") {
		t.Fatalf("expected glob compile error, got %v", err)
	}
}

func TestValidateWatchedProcessDuplicateName(t *testing.T) {
	cfg := Default()
	cfg.Triggers.WatchedProcess = []WatchedProcessTrigger{
		{Name: "dup", ExitCode: "any"},
		{Name: "dup", ExitCode: "any"},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("expected duplicate name error, got %v", err)
	}
}

func TestValidateWatchedProcessEmptyName(t *testing.T) {
	cfg := Default()
	cfg.Triggers.WatchedProcess = []WatchedProcessTrigger{{Name: "", ExitCode: "any"}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "name must not be empty") {
		t.Fatalf("expected empty-name error, got %v", err)
	}
}

func TestValidateReportsMultipleErrors(t *testing.T) {
	cfg := Default()
	cfg.Snapshot.Dir = "relative"
	cfg.Filters.CIDRs = []string{"not-a-cidr"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "absolute path") || !strings.Contains(msg, "not a valid CIDR") {
		t.Fatalf("expected both errors reported together, got: %v", msg)
	}
}

func TestValidateRedactionDuplicateRuleName(t *testing.T) {
	cfg := Default()
	cfg.Redaction.Rules = []RedactionRule{
		{Name: "x", Pattern: "a"},
		{Name: "x", Pattern: "b"},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("expected duplicate rule name error, got %v", err)
	}
}

func TestValidateRedactionUnknownTarget(t *testing.T) {
	cfg := Default()
	cfg.Redaction.Rules = []RedactionRule{{Name: "x", Pattern: "a", Targets: []string{"body"}}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown target") {
		t.Fatalf("expected unknown target error, got %v", err)
	}
}

func TestValidateSignalUnknown(t *testing.T) {
	cfg := Default()
	cfg.Triggers.Signal.Signals = []string{"SIGNOTAREALSIGNAL"}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown signal") {
		t.Fatalf("expected unknown signal error, got %v", err)
	}
}
