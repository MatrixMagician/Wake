//go:build integration

package trigger

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestUnitFailureTriggerViaSDBus discharges the M4 acceptance criterion that
// the systemd-unit-failure trigger fires for real, against a real bus, using a
// purposely-failing transient unit.
//
// It is an integration test rather than a mocked one on purpose: the value of
// this trigger is entirely in whether systemd's PropertiesChanged signals say
// what we think they say, and a mock of our own understanding would prove only
// that we are consistent with ourselves.
func TestUnitFailureTriggerViaSDBus(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a system-scope transient unit")
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run is not available")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("not running under systemd")
	}

	const unit = "wake-integration-failure.service"

	// Clean up any leftover from a previous run, or systemd will refuse the
	// name and the test will fail for an unrelated reason.
	_ = exec.Command("systemctl", "reset-failed", unit).Run()
	t.Cleanup(func() {
		_ = exec.Command("systemctl", "reset-failed", unit).Run()
		_ = exec.Command("systemctl", "stop", unit).Run()
	})

	engine, err := NewEngine([]Rule{{
		Name: "unit-failure", Type: TypeUnit, Unit: "wake-integration-*",
	}}, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	watcher, err := NewUnitWatcher(slog.New(slog.DiscardHandler))
	if err != nil {
		t.Skipf("system bus unavailable: %v", err)
	}
	defer func() { _ = watcher.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Run(ctx, engine)

	// Let the subscription settle before creating the unit, or the signal can
	// be emitted before the match is installed.
	time.Sleep(500 * time.Millisecond)

	// A unit that exits non-zero enters the failed state, which is exactly the
	// transition we subscribe to.
	// systemd-run waits for a oneshot unit and reports its exit status, so a
	// non-zero return here means the unit failed — which is precisely what the
	// test is arranging. The error is therefore deliberately not fatal; what
	// matters is whether the trigger fired, asserted below.
	out, runErr := exec.Command("systemd-run",
		"--unit", unit,
		"--property=Type=oneshot",
		"--property=RemainAfterExit=no",
		"/bin/false",
	).CombinedOutput()
	t.Logf("systemd-run: err=%v output=%s", runErr, out)

	select {
	case f := <-engine.Firings():
		if f.Type != TypeUnit {
			t.Errorf("firing type = %q, want %q", f.Type, TypeUnit)
		}
		if f.Unit != unit {
			t.Errorf("firing unit = %q, want %q", f.Unit, unit)
		}
		if f.Reason == "" {
			t.Error("the firing carries no reason")
		}
	case <-time.After(20 * time.Second):
		state, _ := exec.Command("systemctl", "show", "-p", "ActiveState",
			"--value", unit).Output()
		t.Fatalf("no firing after the unit failed; its ActiveState is %q", state)
	}
}
