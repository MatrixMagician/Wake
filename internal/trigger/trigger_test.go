package trigger

import (
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// fakeClock lets cooldowns be tested in microseconds rather than minutes.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 8, 2, 14, 0, 0, 0, time.UTC)}
}

func exitEvent(comm string, code, sig int32) *event.Event {
	ev := &event.Event{Class: event.ClassExit, PID: 4321}
	ev.Comm = comm
	ev.ExitCode = &code
	if sig != 0 {
		ev.ExitSignal = &sig
	}
	return ev
}

// drain collects everything currently pending without blocking.
func drain(e *Engine) []Firing {
	var out []Firing
	for {
		select {
		case f := <-e.Firings():
			out = append(out, f)
		default:
			return out
		}
	}
}

func mustEngine(t *testing.T, rules []Rule, c Clock) *Engine {
	t.Helper()
	e, err := NewEngine(rules, c)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestProcessTriggerExitPredicates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		pred ExitPredicate
		ev   *event.Event
		want bool
	}{
		{"default matches non-zero exit", ExitPredicate{}, exitEvent("mstr", 1, 0), true},
		{"default matches a signal death", ExitPredicate{}, exitEvent("mstr", 0, 11), true},
		{"default ignores a clean exit", ExitPredicate{}, exitEvent("mstr", 0, 0), false},
		{"specific code matches", ExitPredicate{Codes: []int32{137}}, exitEvent("mstr", 137, 0), true},
		{"specific code ignores others", ExitPredicate{Codes: []int32{137}}, exitEvent("mstr", 1, 0), false},
		{"specific signal matches", ExitPredicate{Signals: []int32{9}}, exitEvent("mstr", 0, 9), true},
		{"any signal matches", ExitPredicate{AnySignal: true}, exitEvent("mstr", 0, 6), true},
		{"any signal ignores a code-only exit", ExitPredicate{AnySignal: true}, exitEvent("mstr", 3, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := mustEngine(t, []Rule{{
				Name: "r", Type: TypeProcess, Comm: "mstr", Exit: tc.pred,
			}}, newClock())
			e.Observe(tc.ev)
			got := len(drain(e)) == 1
			if got != tc.want {
				t.Errorf("fired = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScopeGlobs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		rule Rule
		comm string
		unit string
		want bool
	}{
		{"empty glob matches anything", Rule{Name: "r", Type: TypeProcess}, "anything", "", true},
		{"comm glob matches", Rule{Name: "r", Type: TypeProcess, Comm: "mstr*"}, "mstrsvr", "", true},
		{"comm glob rejects", Rule{Name: "r", Type: TypeProcess, Comm: "mstr*"}, "nginx", "", false},
		{"unit glob matches", Rule{Name: "r", Type: TypeProcess, Unit: "*.service"}, "x", "mstr.service", true},
		{"unit glob rejects", Rule{Name: "r", Type: TypeProcess, Unit: "*.service"}, "x", "user.slice", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := mustEngine(t, []Rule{tc.rule}, newClock())
			ev := exitEvent(tc.comm, 1, 0)
			ev.Unit = tc.unit
			e.Observe(ev)
			if got := len(drain(e)) == 1; got != tc.want {
				t.Errorf("fired = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCooldownPreventsStorms is the acceptance criterion from SPEC.md M4: a
// crash-looping service must produce one snapshot, not forty.
func TestCooldownPreventsStorms(t *testing.T) {
	t.Parallel()
	c := newClock()
	e := mustEngine(t, []Rule{{
		Name: "crashloop", Type: TypeProcess, Comm: "mstr", Cooldown: time.Minute,
	}}, c)

	for range 40 {
		e.Observe(exitEvent("mstr", 1, 0))
		c.advance(time.Second)
	}
	if got := len(drain(e)); got != 1 {
		t.Fatalf("fired %d times during a crash loop, want 1", got)
	}
	if got := e.Suppressed()["crashloop"]; got != 39 {
		t.Errorf("suppressed = %d, want 39; an operator must be told what the cooldown swallowed", got)
	}

	// Past the cooldown, the rule fires again.
	c.advance(2 * time.Minute)
	e.Observe(exitEvent("mstr", 1, 0))
	if got := len(drain(e)); got != 1 {
		t.Errorf("fired %d times after the cooldown elapsed, want 1", got)
	}
}

func TestOOMAndSignalTriggers(t *testing.T) {
	t.Parallel()
	t.Run("oom anywhere in scope", func(t *testing.T) {
		e := mustEngine(t, []Rule{{Name: "oom", Type: TypeOOM}}, newClock())
		ev := &event.Event{Class: event.ClassOOM, PID: 99}
		ev.Comm = "hungry"
		e.Observe(ev)
		f := drain(e)
		if len(f) != 1 || f[0].Type != TypeOOM {
			t.Fatalf("firings = %+v", f)
		}
		if f[0].Reason == "" {
			t.Error("a firing must explain itself; it is the first thing anyone reads")
		}
	})

	t.Run("signal allow list", func(t *testing.T) {
		e := mustEngine(t, []Rule{{
			Name: "segv", Type: TypeSignal, Signals: []int32{11},
		}}, newClock())

		sig := int32(15)
		ev := &event.Event{Class: event.ClassSignal, Signal: &sig}
		e.Observe(ev)
		if got := len(drain(e)); got != 0 {
			t.Errorf("SIGTERM fired a SIGSEGV rule %d times", got)
		}

		sig = 11
		e.Observe(&event.Event{Class: event.ClassSignal, Signal: &sig})
		if got := len(drain(e)); got != 1 {
			t.Errorf("SIGSEGV fired %d times, want 1", got)
		}
	})
}

func TestManualAndUnitTriggers(t *testing.T) {
	t.Parallel()
	t.Run("manual always fires", func(t *testing.T) {
		e := mustEngine(t, nil, newClock())
		e.Manual("operator investigating a stall")
		f := drain(e)
		if len(f) != 1 || f[0].Type != TypeManual {
			t.Fatalf("firings = %+v", f)
		}
		if f[0].Reason != "operator investigating a stall" {
			t.Errorf("reason = %q; the operator's own words must survive", f[0].Reason)
		}
	})

	t.Run("manual with no reason still explains itself", func(t *testing.T) {
		e := mustEngine(t, nil, newClock())
		e.Manual("")
		if f := drain(e); len(f) != 1 || f[0].Reason == "" {
			t.Errorf("firings = %+v", f)
		}
	})

	t.Run("unit failure", func(t *testing.T) {
		e := mustEngine(t, []Rule{{Name: "u", Type: TypeUnit, Unit: "mstr*.service"}}, newClock())
		e.UnitFailed("nginx.service")
		if got := len(drain(e)); got != 0 {
			t.Errorf("unrelated unit fired %d times", got)
		}
		e.UnitFailed("mstr-iserver.service")
		f := drain(e)
		if len(f) != 1 || f[0].Unit != "mstr-iserver.service" {
			t.Fatalf("firings = %+v", f)
		}
	})
}

func TestRuleValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		rule Rule
	}{
		{"no name", Rule{Type: TypeProcess}},
		{"unknown type", Rule{Name: "r", Type: "telepathy"}},
		{"negative cooldown", Rule{Name: "r", Type: TypeOOM, Cooldown: -time.Second}},
		{"malformed glob", Rule{Name: "r", Type: TypeProcess, Comm: "["}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewEngine([]Rule{tc.rule}, newClock()); err == nil {
				t.Error("invalid rule accepted; it would only be discovered during an incident")
			}
		})
	}
}

func TestFiringSlugIsFilesystemSafe(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		f    Firing
		want string
	}{
		{Firing{Type: TypeOOM, Comm: "my proc/1"}, "oom-my_proc_1"},
		{Firing{Type: TypeUnit, Unit: "mstr.service"}, "unit-mstr"},
		{Firing{Type: TypeManual}, "manual"},
	} {
		if got := tc.f.Slug(); got != tc.want {
			t.Errorf("Slug() = %q, want %q", got, tc.want)
		}
	}
}

func TestUnitFromPathDecodesSystemdEscaping(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ path, want string }{
		{"/org/freedesktop/systemd1/unit/mstr_2diserver_2eservice", "mstr-iserver.service"},
		{"/org/freedesktop/systemd1/unit/sshd_2eservice", "sshd.service"},
		{"/some/other/path", ""},
	} {
		if got := unitFromPath(tc.path); got != tc.want {
			t.Errorf("unitFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestObserveNeverBlocks proves the recorder cannot be stalled by a busy
// snapshot writer: a stalled recorder loses the very events the snapshot is
// meant to contain.
func TestObserveNeverBlocks(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, []Rule{{Name: "r", Type: TypeProcess}}, newClock())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			e.Observe(exitEvent("x", 1, 0))
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Observe blocked when nothing was draining the firing channel")
	}
	if e.Suppressed()["r"] == 0 {
		t.Error("firings dropped by a full channel must still be counted")
	}
}
