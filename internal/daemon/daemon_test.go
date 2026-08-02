package daemon

import (
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/config"
	"github.com/MatrixMagician/wake/internal/event"
	"github.com/MatrixMagician/wake/internal/trigger"
)

// These tests cover the translation layer, which is where a configuration
// mistake would otherwise become a silent kernel-filter mistake, and the
// daemon's own locking, which a live run found a bug in once already.

func TestExpandPorts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		in      []string
		want    []uint16
		wantErr bool
	}{
		{"single", []string{"443"}, []uint16{443}, false},
		{"several", []string{"80", "443"}, []uint16{80, 443}, false},
		{"range", []string{"8000-8003"}, []uint16{8000, 8001, 8002, 8003}, false},
		{"whitespace tolerated", []string{" 80 - 81 "}, []uint16{80, 81}, false},
		{"inverted range", []string{"90-80"}, nil, true},
		{"not a number", []string{"http"}, nil, true},
		{"out of range", []string{"70000"}, nil, true},
		{"range wider than the kernel map", []string{"1-4000"}, nil, true},
		{"empty", nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandPorts(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expandPorts(%q) succeeded; a filter that silently "+
						"does the wrong thing is the failure this project refuses", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandPorts(%q): %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestLoaderOptionsFromConfig(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Scope.CgroupSubtree = "/system.slice/mstr.service"
	cfg.Scope.CommAllow = []string{"mstr"}
	cfg.Filters.PathPrefixes = []string{"/etc"}
	cfg.Filters.Ports = []string{"443"}
	cfg.Filters.CIDRs = []string{"10.0.0.0/8"}

	opts, err := loaderOptions(cfg)
	if err != nil {
		t.Fatalf("loaderOptions: %v", err)
	}

	if len(opts.CgroupPaths) != 1 || opts.CgroupPaths[0] != "/system.slice/mstr.service" {
		t.Errorf("cgroup paths = %v", opts.CgroupPaths)
	}
	if len(opts.Ports) != 1 || opts.Ports[0] != 443 {
		t.Errorf("ports = %v", opts.Ports)
	}
	if len(opts.CIDRs) != 1 || opts.CIDRs[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("cidrs = %v", opts.CIDRs)
	}
	if opts.SelfPID == 0 {
		t.Error("SelfPID must be set, or the recorder observes itself")
	}
	if err := opts.Validate(); err != nil {
		t.Errorf("options translated from a valid config do not validate: %v", err)
	}
}

func TestLoaderOptionsRejectsBadCIDR(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Filters.CIDRs = []string{"not-a-network"}
	if _, err := loaderOptions(cfg); err == nil {
		t.Error("a malformed CIDR was accepted")
	}
}

func TestTriggerRulesFromConfig(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Triggers.WatchedProcess = []config.WatchedProcessTrigger{{
		Name: "mstr-death", CommGlob: "mstr*", ExitCode: "nonzero", Cooldown: 5 * time.Minute,
	}}
	cfg.Triggers.OOM = config.OOMTrigger{Enabled: true, Cooldown: time.Minute}
	cfg.Triggers.Signal = config.SignalTrigger{
		Enabled: true, Signals: []string{"SIGSEGV"}, Cooldown: time.Minute,
	}
	cfg.Triggers.UnitFailed = config.UnitFailedTrigger{
		Enabled: true, Units: []string{"mstr*.service"}, Cooldown: time.Minute,
	}

	rules, err := triggerRules(cfg)
	if err != nil {
		t.Fatalf("triggerRules: %v", err)
	}

	byType := map[trigger.Type]int{}
	for _, r := range rules {
		byType[r.Type]++
		if err := r.Validate(); err != nil {
			t.Errorf("rule %q translated from a valid config is invalid: %v", r.Name, err)
		}
	}
	for _, typ := range []trigger.Type{
		trigger.TypeProcess, trigger.TypeOOM, trigger.TypeSignal, trigger.TypeUnit,
	} {
		if byType[typ] == 0 {
			t.Errorf("no %q rule was produced", typ)
		}
	}

	// The engine must accept the whole set, which is the real assertion: a
	// rule that only fails at NewEngine fails during someone's incident.
	if _, err := trigger.NewEngine(rules, nil); err != nil {
		t.Errorf("engine rejected translated rules: %v", err)
	}
}

func TestTriggerRulesRejectsBadExitPredicate(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Triggers.WatchedProcess = []config.WatchedProcessTrigger{{
		Name: "bad", ExitCode: "any-nonzero",
	}}
	if _, err := triggerRules(cfg); err == nil {
		t.Error("an unparseable exit predicate was accepted")
	}
}

// TestExitPredicateBridge checks the config→trigger predicate bridge against
// the behaviours the grammar promises.
func TestExitPredicateBridge(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		spec      string
		code      int32
		bySignal  bool
		wantMatch bool
	}{
		{"nonzero", 1, false, true},
		{"nonzero", 0, false, false},
		{"signal", 9, true, true},
		{"137", 137, false, true},
		{"137", 1, false, false},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			p, err := config.ParseExitCodePredicate(tc.spec)
			if err != nil {
				t.Fatalf("ParseExitCodePredicate(%q): %v", tc.spec, err)
			}
			bridged := exitPredicate(p)

			ev := exitEventFor(tc.code, tc.bySignal)
			if got := bridged.Matches(ev); got != tc.wantMatch {
				t.Errorf("predicate %q on code=%d signal=%v: matched=%v, want %v",
					tc.spec, tc.code, tc.bySignal, got, tc.wantMatch)
			}
		})
	}
}

// TestDaemonStatusIsLockSafe exercises the status path concurrently with
// snapshot bookkeeping. A live run once found an unbalanced mutex here; this
// is the test that would have found it first.
func TestDaemonStatusIsLockSafe(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Snapshot.Dir = t.TempDir()

	d, err := New(cfg, socketInTempDir(t), discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = d.srv.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			_ = d.Status()
		}
	}()
	for range 200 {
		d.mu.Lock()
		d.snapshots++
		d.mu.Unlock()
	}
	<-done
}

// Helpers, kept at the bottom so the tests above read as behaviour.

func exitEventFor(code int32, bySignal bool) *event.Event {
	ev := &event.Event{Class: event.ClassExit}
	if bySignal {
		sig := code
		ev.ExitSignal = &sig
		zero := int32(0)
		ev.ExitCode = &zero
		return ev
	}
	c := code
	ev.ExitCode = &c
	return ev
}

func socketInTempDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "wake.sock")
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
