// Package trigger decides when a snapshot should be taken.
//
// The engine is deliberately ignorant of what a snapshot *is*: it evaluates
// rules against events and external notifications and emits a Firing. That
// separation is what lets every rule type be unit-tested without a kernel, a
// systemd bus, or a filesystem.
package trigger

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"sync"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// Type names the five trigger kinds from SPEC.md §2 goal 4.
type Type string

const (
	// TypeProcess fires when a watched process exits in a way the rule's
	// predicate matches.
	TypeProcess Type = "process"
	// TypeOOM fires on an OOM kill anywhere in scope.
	TypeOOM Type = "oom"
	// TypeSignal fires when a configured signal is delivered in scope.
	TypeSignal Type = "signal"
	// TypeManual fires on `wake trigger`, SIGUSR1, or a socket request.
	TypeManual Type = "manual"
	// TypeUnit fires when a systemd unit enters the failed state.
	TypeUnit Type = "unit"
)

// ExitPredicate constrains which exits count. The zero value matches any
// abnormal exit, which is the useful default: a service that exits cleanly is
// rarely an incident.
type ExitPredicate struct {
	// AnyNonZero matches any non-zero exit code or any terminating signal.
	AnyNonZero bool
	// Codes matches these exact exit codes.
	Codes []int32
	// Signals matches these terminating signals.
	Signals []int32
	// AnySignal matches death by any signal.
	AnySignal bool
}

// IsZero reports whether the predicate constrains nothing, in which case the
// AnyNonZero default applies.
func (p ExitPredicate) IsZero() bool {
	return !p.AnyNonZero && !p.AnySignal && len(p.Codes) == 0 && len(p.Signals) == 0
}

// Matches evaluates the predicate against an exit event.
func (p ExitPredicate) Matches(ev *event.Event) bool {
	code, sig := int32(0), int32(0)
	if ev.ExitCode != nil {
		code = *ev.ExitCode
	}
	if ev.ExitSignal != nil {
		sig = *ev.ExitSignal
	}

	if p.IsZero() || p.AnyNonZero {
		return code != 0 || sig != 0
	}
	if p.AnySignal && sig != 0 {
		return true
	}
	for _, c := range p.Codes {
		if code == c {
			return true
		}
	}
	for _, s := range p.Signals {
		if sig == s {
			return true
		}
	}
	return false
}

// Rule is one configured trigger. Every rule has a cooldown, without which a
// crash-looping service would fill the snapshot directory in seconds
// (CONTEXT.md, "Trigger").
type Rule struct {
	Name     string
	Type     Type
	Cooldown time.Duration

	// Comm, Unit and Cgroup are globs matched against the event's attribution.
	// An empty glob matches everything of the rule's type.
	Comm   string
	Unit   string
	Cgroup string

	// Exit constrains TypeProcess rules.
	Exit ExitPredicate

	// Signals constrains TypeSignal rules. Empty means any signal that
	// reached the recorder, which the kernel-side allow list already narrowed.
	Signals []int32
}

// Validate checks a rule in isolation so that a bad configuration is rejected
// at start-up rather than discovered during an incident.
func (r Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("trigger rule has no name")
	}
	switch r.Type {
	case TypeProcess, TypeOOM, TypeSignal, TypeManual, TypeUnit:
	default:
		return fmt.Errorf("rule %q: unknown trigger type %q", r.Name, r.Type)
	}
	if r.Cooldown < 0 {
		return fmt.Errorf("rule %q: cooldown must not be negative", r.Name)
	}
	for _, g := range []struct{ field, glob string }{
		{"comm", r.Comm}, {"unit", r.Unit}, {"cgroup", r.Cgroup},
	} {
		if g.glob == "" {
			continue
		}
		if _, err := path.Match(g.glob, ""); err != nil {
			return fmt.Errorf("rule %q: %s glob %q is malformed: %w", r.Name, g.field, g.glob, err)
		}
	}
	return nil
}

// Firing describes why a snapshot is being taken. It is recorded verbatim in
// the snapshot manifest, because "why do I have this snapshot?" is the first
// question anyone asks of one.
type Firing struct {
	Rule   string       `json:"rule"`
	Type   Type         `json:"type"`
	At     time.Time    `json:"at"`
	Reason string       `json:"reason"`
	PID    int32        `json:"pid,omitempty"`
	Comm   string       `json:"comm,omitempty"`
	Unit   string       `json:"unit,omitempty"`
	Cgroup string       `json:"cgroup,omitempty"`
	Event  *event.Event `json:"-"`
}

// Clock is injectable so that cooldown behaviour can be tested in
// microseconds rather than in real minutes.
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Engine evaluates rules and emits firings. It is safe for concurrent use:
// events arrive from the recorder goroutine while manual triggers arrive from
// the control socket.
type Engine struct {
	mu       sync.Mutex
	rules    []Rule
	lastFire map[string]time.Time
	clock    Clock

	// Suppressed counts firings that a cooldown swallowed. An operator who
	// sees one snapshot for a crash loop needs to know the other forty
	// happened, so this is reported in status and in the manifest.
	suppressed map[string]uint64

	out chan Firing
}

// NewEngine constructs an engine. A nil clock means the real one.
func NewEngine(rules []Rule, clock Clock) (*Engine, error) {
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return nil, err
		}
	}
	if clock == nil {
		clock = realClock{}
	}
	return &Engine{
		rules:      rules,
		lastFire:   make(map[string]time.Time, len(rules)),
		suppressed: make(map[string]uint64, len(rules)),
		clock:      clock,
		// Buffered so that a slow snapshot writer cannot stall the recorder;
		// a full channel means we are already writing, and the cooldown would
		// most likely have suppressed the firing anyway.
		out: make(chan Firing, 8),
	}, nil
}

// Firings is the channel snapshots are taken from.
func (e *Engine) Firings() <-chan Firing { return e.out }

// Observe evaluates an event against every rule. It never blocks.
func (e *Engine) Observe(ev *event.Event) {
	switch ev.Class {
	case event.ClassExit:
		e.evaluate(ev, TypeProcess)
	case event.ClassOOM:
		e.evaluate(ev, TypeOOM)
	case event.ClassSignal:
		e.evaluate(ev, TypeSignal)
	default:
	}
}

func (e *Engine) evaluate(ev *event.Event, typ Type) {
	for i := range e.rules {
		r := e.rules[i]
		if r.Type != typ || !r.scopeMatches(ev) {
			continue
		}
		switch typ {
		case TypeProcess:
			if !r.Exit.Matches(ev) {
				continue
			}
		case TypeSignal:
			if !r.signalMatches(ev) {
				continue
			}
		default:
		}
		e.fire(r, Firing{
			Rule:   r.Name,
			Type:   typ,
			Reason: describe(typ, ev),
			PID:    ev.PID,
			Comm:   ev.Comm,
			Unit:   ev.Unit,
			Cgroup: ev.Cgroup,
			Event:  ev,
		})
	}
}

func (r Rule) scopeMatches(ev *event.Event) bool {
	return globMatch(r.Comm, ev.Comm) &&
		globMatch(r.Unit, ev.Unit) &&
		globMatch(r.Cgroup, ev.Cgroup)
}

func (r Rule) signalMatches(ev *event.Event) bool {
	if len(r.Signals) == 0 {
		return true
	}
	if ev.Signal == nil {
		return false
	}
	return slices.Contains(r.Signals, *ev.Signal)
}

// globMatch treats an empty pattern as "match anything". A malformed pattern
// matches nothing, having already been rejected by Validate; failing closed
// here means a late corruption cannot cause a snapshot storm.
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return true
	}
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}

func describe(typ Type, ev *event.Event) string {
	switch typ {
	case TypeProcess:
		switch {
		case ev.ExitSignal != nil && *ev.ExitSignal != 0:
			return fmt.Sprintf("%s (pid %d) was killed by %s", ev.Comm, ev.PID, ev.SignalName)
		case ev.ExitCode != nil:
			return fmt.Sprintf("%s (pid %d) exited with code %d", ev.Comm, ev.PID, *ev.ExitCode)
		default:
			return fmt.Sprintf("%s (pid %d) exited", ev.Comm, ev.PID)
		}
	case TypeOOM:
		return fmt.Sprintf("%s (pid %d) was killed by the OOM killer", ev.Comm, ev.PID)
	case TypeSignal:
		return fmt.Sprintf("%s was delivered to %s (pid %d)", ev.SignalName, ev.Comm, ev.PID)
	default:
		return string(typ)
	}
}

// Manual fires the built-in manual rule, used by `wake trigger`, SIGUSR1 and
// the control socket. It bypasses no cooldown: an operator asking twice in a
// second means the same thing a crash loop does.
func (e *Engine) Manual(reason string) {
	if reason == "" {
		reason = "operator requested a snapshot"
	}
	e.fire(Rule{Name: "manual", Type: TypeManual}, Firing{
		Rule:   "manual",
		Type:   TypeManual,
		Reason: reason,
	})
}

// UnitFailed fires for a systemd unit that entered the failed state. It is
// called by the sd-bus watcher, which lives in its own file so that this
// package's tests need no bus.
func (e *Engine) UnitFailed(unit string) {
	for i := range e.rules {
		r := e.rules[i]
		if r.Type != TypeUnit || !globMatch(r.Unit, unit) {
			continue
		}
		e.fire(r, Firing{
			Rule:   r.Name,
			Type:   TypeUnit,
			Unit:   unit,
			Reason: fmt.Sprintf("unit %s entered the failed state", unit),
		})
	}
}

// fire applies the cooldown and emits, counting anything it suppresses.
func (e *Engine) fire(r Rule, f Firing) {
	e.mu.Lock()
	now := e.clock.Now()
	if last, seen := e.lastFire[r.Name]; seen && r.Cooldown > 0 && now.Sub(last) < r.Cooldown {
		e.suppressed[r.Name]++
		e.mu.Unlock()
		return
	}
	e.lastFire[r.Name] = now
	e.mu.Unlock()

	f.At = now
	select {
	case e.out <- f:
	default:
		// The writer is busy. Count it rather than block the recorder: a
		// stalled recorder loses the very events the snapshot is meant to
		// contain.
		e.mu.Lock()
		e.suppressed[r.Name]++
		e.mu.Unlock()
	}
}

// Suppressed reports per-rule suppression counts, so that `wake status` and
// every manifest can say how many firings a cooldown swallowed.
func (e *Engine) Suppressed() map[string]uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return maps.Clone(e.suppressed)
}
