package daemon

import (
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/config"
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
	// CIDRs are deliberately not part of the loader's options: they are
	// applied in userspace by the recorder (ADR 0002), so a reader of the
	// kernel-facing struct cannot mistake them for an in-kernel guarantee.
	cidrs, err := filterCIDRs(cfg)
	if err != nil {
		t.Fatalf("filterCIDRs: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("cidrs = %v", cidrs)
	}
	if opts.SelfPID == 0 {
		t.Error("SelfPID must be set, or the recorder observes itself")
	}
	if err := opts.Validate(); err != nil {
		t.Errorf("options translated from a valid config do not validate: %v", err)
	}
}

func TestFilterCIDRsRejectsBadCIDR(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Filters.CIDRs = []string{"not-a-network"}
	if _, err := filterCIDRs(cfg); err == nil {
		t.Error("a malformed CIDR was accepted")
	}
}

// TestFilterCIDRsMasksHostBits pins that a prefix written with host bits set
// means the network the operator intended, not a single address.
func TestFilterCIDRsMasksHostBits(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Filters.CIDRs = []string{"10.1.2.3/8"}
	got, err := filterCIDRs(cfg)
	if err != nil {
		t.Fatalf("filterCIDRs: %v", err)
	}
	if want := netip.MustParsePrefix("10.0.0.0/8"); got[0] != want {
		t.Errorf("prefix = %v, want %v", got[0], want)
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

// TestWatchedProcessExitPredicate checks that the config grammar reaches the
// engine meaning what it says.
func TestWatchedProcessExitPredicate(t *testing.T) {
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
		// The grammar says a comparison never matches a death by signal, since
		// there is no code to compare. The struct-shaped bridge this replaced
		// promoted any predicate that happened to accept code 1 into "any
		// abnormal exit", so ">0" fired on a SIGSEGV and "<5" fired on code 200.
		{">0", 5, false, true},
		{">0", 0, true, false},
		{"<5", 1, false, true},
		{"<5", 200, false, false},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			cfg := config.Default()
			cfg.Triggers.WatchedProcess = []config.WatchedProcessTrigger{
				{Name: "w", ExitCode: tc.spec},
			}
			rules, err := triggerRules(cfg)
			if err != nil {
				t.Fatalf("triggerRules: %v", err)
			}
			if rules[0].Exit == nil {
				t.Fatalf("exit_code %q compiled to a nil predicate", tc.spec)
			}
			if got := rules[0].Exit(tc.code, tc.bySignal); got != tc.wantMatch {
				t.Errorf("predicate %q on code=%d signal=%v: matched=%v, want %v",
					tc.spec, tc.code, tc.bySignal, got, tc.wantMatch)
			}
		})
	}
}

// TestUnsetExitCodeKeepsTheAbnormalExitDefault pins the distinction between an
// unset exit_code and an explicit "any". Unset must leave the predicate nil so
// the engine applies its own default; "any" means what it says and fires on a
// clean exit too.
func TestUnsetExitCodeKeepsTheAbnormalExitDefault(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Triggers.WatchedProcess = []config.WatchedProcessTrigger{
		{Name: "unset"}, {Name: "explicit", ExitCode: "any"},
	}
	rules, err := triggerRules(cfg)
	if err != nil {
		t.Fatalf("triggerRules: %v", err)
	}
	if rules[0].Exit != nil {
		t.Error("an unset exit_code should leave Exit nil so the engine's abnormal-exit default applies")
	}
	if rules[1].Exit == nil {
		t.Fatal(`an explicit "any" should compile to a predicate`)
	}
	if !rules[1].Exit(0, false) {
		t.Error(`exit_code = "any" should match a clean exit; the grammar says any exit`)
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

func socketInTempDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "wake.sock")
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
