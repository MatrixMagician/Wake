package recorder

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/decode"
	"github.com/MatrixMagician/wake/internal/event"
	"github.com/MatrixMagician/wake/internal/loader"
	"github.com/MatrixMagician/wake/internal/ring"
	"github.com/MatrixMagician/wake/internal/trigger"
)

// fakeSource replays records the test constructed. It is the seam that makes
// the whole daemon loop testable with no kernel and no privileges, which is
// the point of loader.Source existing at all.
type fakeSource struct {
	ch     chan loader.Record
	mu     sync.Mutex
	drops  map[string]uint64
	closed bool
}

func newFakeSource() *fakeSource {
	return &fakeSource{ch: make(chan loader.Record, 64), drops: map[string]uint64{}}
}

func (s *fakeSource) Records() <-chan loader.Record { return s.ch }

func (s *fakeSource) KernelDrops() (map[string]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.drops))
	for k, v := range s.drops {
		out[k] = v
	}
	return out, nil
}

func (s *fakeSource) setDrops(class string, n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drops[class] = n
}

func (s *fakeSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
	return nil
}

// Wire-format helpers, mirroring bpf/wake_event.h. Kept minimal: the decoder's
// own tests cover the layouts exhaustively.
const (
	headerSize = 56
	exitSize   = 72
	execSize   = 840
)

func exitRecord(pid int32, comm string, code int32) loader.Record {
	b := make([]byte, exitSize)
	binary.LittleEndian.PutUint64(b[0:], 1_000_000)
	binary.LittleEndian.PutUint32(b[8:], 2) // exit
	binary.LittleEndian.PutUint32(b[12:], decode.WireVersion)
	binary.LittleEndian.PutUint32(b[16:], uint32(pid)) //nolint:gosec
	binary.LittleEndian.PutUint32(b[20:], uint32(pid)) //nolint:gosec
	copy(b[40:56], comm)
	binary.LittleEndian.PutUint32(b[headerSize:], uint32(code)) //nolint:gosec
	return loader.Record{Raw: b}
}

func execRecord(pid int32, comm, argv string) loader.Record {
	b := make([]byte, execSize)
	binary.LittleEndian.PutUint64(b[0:], 1_000_000)
	binary.LittleEndian.PutUint32(b[8:], 1) // exec
	binary.LittleEndian.PutUint32(b[12:], decode.WireVersion)
	binary.LittleEndian.PutUint32(b[16:], uint32(pid)) //nolint:gosec
	copy(b[40:56], comm)
	binary.LittleEndian.PutUint32(b[60:], uint32(len(argv))) //nolint:gosec
	copy(b[324:], argv)
	return loader.Record{Raw: b}
}

// stubEnricher records what it saw and stamps a fixed unit, so that unit
// filtering can be tested without a cgroup hierarchy.
type stubEnricher struct {
	mu       sync.Mutex
	observed int
	unit     string
}

func (e *stubEnricher) Observe(event.Event) {
	e.mu.Lock()
	e.observed++
	e.mu.Unlock()
}

func (e *stubEnricher) Resolve(ev *event.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.unit != "" {
		ev.Unit = e.unit
	}
}

func (e *stubEnricher) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.observed
}

// stubRedactor masks a fixed secret, so that the ordering guarantee (redact
// before the ring, not at snapshot time) can be asserted directly.
type stubRedactor struct{ secret string }

func (r stubRedactor) Redact(ev *event.Event) {
	for i, a := range ev.Argv {
		if strings.Contains(a, r.secret) {
			ev.Argv[i] = strings.ReplaceAll(a, r.secret, "[REDACTED]")
		}
	}
}

type harness struct {
	rec    *Recorder
	src    *fakeSource
	ring   *ring.Ring
	drops  *event.Drops
	enrich *stubEnricher
	trig   *trigger.Engine
	cancel context.CancelFunc
	done   chan struct{}
}

func newHarness(t *testing.T, rules []trigger.Rule, redactor Redactor) *harness {
	t.Helper()
	return newHarnessWithCIDRs(t, rules, redactor, nil)
}

func newHarnessWithCIDRs(t *testing.T, rules []trigger.Rule, redactor Redactor,
	cidrs []netip.Prefix) *harness {
	t.Helper()

	drops := &event.Drops{}
	rg, err := ring.New(time.Hour, 1000, 1<<20, drops)
	if err != nil {
		t.Fatalf("ring.New: %v", err)
	}
	eng, err := trigger.NewEngine(rules, nil)
	if err != nil {
		t.Fatalf("trigger.NewEngine: %v", err)
	}

	src := newFakeSource()
	enr := &stubEnricher{}
	rec := New(Options{
		Source:             src,
		Decoder:            decode.New(decode.BootClock{Boot: time.Now().Add(-time.Hour)}),
		Ring:               rg,
		Enricher:           enr,
		Redactor:           redactor,
		Triggers:           eng,
		Drops:              drops,
		Logger:             slog.New(slog.DiscardHandler),
		KernelDropInterval: 5 * time.Millisecond,
		CIDRs:              cidrs,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = rec.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return &harness{rec: rec, src: src, ring: rg, drops: drops,
		enrich: enr, trig: eng, cancel: cancel, done: done}
}

// waitFor polls until cond holds, so that tests assert on outcomes rather than
// on sleeps.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRecordsFlowIntoTheRing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil, nil)

	for i := range 5 {
		h.src.ch <- exitRecord(int32(100+i), "svc", 1) //nolint:gosec
	}
	waitFor(t, "events in the ring", func() bool { return h.ring.Len() == 5 })

	if got := h.enrich.count(); got != 5 {
		t.Errorf("enricher observed %d events, want 5", got)
	}
}

// TestRedactionHappensBeforeTheRing is the privacy guarantee: a secret that
// never enters the ring cannot leak through a snapshot or a watch stream.
func TestRedactionHappensBeforeTheRing(t *testing.T) {
	t.Parallel()
	const secret = "hunter2"
	h := newHarness(t, nil, stubRedactor{secret: secret})

	h.src.ch <- execRecord(200, "psql", "psql\x00--password="+secret+"\x00")
	waitFor(t, "the exec event", func() bool { return h.ring.Len() == 1 })

	events, _ := h.ring.Freeze()
	for _, ev := range events {
		line, err := ev.MarshalJSONLine()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(line), secret) {
			t.Fatalf("the secret reached the ring: %s", line)
		}
	}
}

func TestTriggersFireFromRecordedEvents(t *testing.T) {
	t.Parallel()
	h := newHarness(t, []trigger.Rule{{
		Name: "crash", Type: trigger.TypeProcess, Comm: "svc",
	}}, nil)

	h.src.ch <- exitRecord(300, "svc", 137)

	select {
	case f := <-h.trig.Firings():
		if f.Rule != "crash" || f.PID != 300 {
			t.Errorf("firing = %+v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no trigger fired for an abnormal exit")
	}
}

func TestWatchFanOutAndSlowWatcherAccounting(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil, nil)

	ch, cancel := h.rec.Subscribe(nil, "")
	h.src.ch <- exitRecord(400, "svc", 0)

	select {
	case ev := <-ch:
		if ev.PID != 400 {
			t.Errorf("watcher saw pid %d", ev.PID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher received nothing")
	}
	cancel()

	// A watcher that never reads must lose events, and every loss must be
	// counted: watch is a tuning aid and always loses before the recorder.
	_, cancel2 := h.rec.Subscribe(nil, "")
	defer cancel2()
	for i := range 600 {
		h.src.ch <- exitRecord(int32(500+i), "svc", 0) //nolint:gosec
	}
	waitFor(t, "watch-boundary drops to be counted", func() bool {
		return h.drops.Get(event.BoundaryWatch, event.ClassExit) > 0
	})
}

func TestWatchClassFilter(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil, nil)

	ch, cancel := h.rec.Subscribe([]string{"exec"}, "")
	defer cancel()

	h.src.ch <- exitRecord(600, "svc", 0)
	h.src.ch <- execRecord(601, "svc", "svc\x00")

	select {
	case ev := <-ch:
		if ev.Class != event.ClassExec {
			t.Errorf("class filter leaked a %q event", ev.Class)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("filtered watcher received nothing")
	}
}

// TestKernelDropsAreSurfaced proves the kernel's own counters reach the shared
// report, so that a snapshot's drop stats are complete rather than merely
// userspace-complete.
func TestKernelDropsAreSurfaced(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil, nil)

	h.src.setDrops("exec", 17)
	waitFor(t, "kernel drop counters to be synced", func() bool {
		return h.drops.Get(event.BoundaryKernel, event.ClassExec) == 17
	})
}

// TestUndecodableRecordsAreKept is the totality rule seen from the daemon's
// point of view: rubbish from the kernel becomes a generic event in the ring,
// not a hole in the record.
func TestUndecodableRecordsAreKept(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil, nil)

	h.src.ch <- loader.Record{Raw: []byte{0xde, 0xad, 0xbe, 0xef}}
	waitFor(t, "the generic event", func() bool { return h.ring.Len() == 1 })

	events, _ := h.ring.Freeze()
	if events[0].Class != event.ClassGeneric {
		t.Fatalf("class = %q, want generic", events[0].Class)
	}
	if len(events[0].Raw) != 4 {
		t.Error("raw payload was not retained")
	}
}

// TestRecordingContinuesThroughAFreeze is the M4 acceptance criterion: events
// generated during snapshot writing appear in the next ring rather than being
// lost.
func TestRecordingContinuesThroughAFreeze(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil, nil)

	h.src.ch <- exitRecord(700, "svc", 0)
	waitFor(t, "the first event", func() bool { return h.ring.Len() == 1 })

	frozen, report := h.rec.Freeze()
	if len(frozen) != 1 {
		t.Fatalf("froze %d events, want 1", len(frozen))
	}
	if report == nil {
		t.Error("a freeze must carry the drop report with it")
	}

	h.src.ch <- exitRecord(701, "svc", 0)
	waitFor(t, "the post-freeze event", func() bool { return h.ring.Len() == 1 })

	next, _ := h.rec.Freeze()
	if len(next) != 1 || next[0].PID != 701 {
		t.Errorf("post-freeze ring = %+v", next)
	}
}

func TestRunStopsWhenTheSourceCloses(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil, nil)
	_ = h.src.Close()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the source closed")
	}
}

// connectRecord builds a connect record with the given destination address.
// family is AF_INET (2) or AF_INET6 (10); addr must be 4 or 16 bytes.
func connectRecord(pid int32, comm string, family uint16, addr []byte) loader.Record {
	const connectSize = headerSize + 4 + 4 + 2 + 2 + 2 + 2 + 16 + 16
	b := make([]byte, connectSize)
	binary.LittleEndian.PutUint64(b[0:], 1_000_000)
	binary.LittleEndian.PutUint32(b[8:], 6) // connect
	binary.LittleEndian.PutUint32(b[12:], decode.WireVersion)
	binary.LittleEndian.PutUint32(b[16:], uint32(pid)) //nolint:gosec
	copy(b[40:56], comm)
	binary.LittleEndian.PutUint32(b[headerSize:], 2)   // old state: SYN_SENT
	binary.LittleEndian.PutUint32(b[headerSize+4:], 1) // new state: ESTABLISHED
	binary.LittleEndian.PutUint16(b[headerSize+12:], family)
	binary.LittleEndian.PutUint16(b[headerSize+14:], 6) // tcp
	copy(b[headerSize+16+16:], addr)                    // daddr
	return loader.Record{Raw: b}
}

// TestCIDRFilterScopesConnectEvents covers the userspace destination filter
// that ADR 0002 specified. Before it was implemented, filters.cidrs was
// parsed, validated, and then silently ignored.
func TestCIDRFilterScopesConnectEvents(t *testing.T) {
	t.Parallel()
	h := newHarnessWithCIDRs(t, nil, nil, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})

	h.src.ch <- connectRecord(1, "inside", 2, []byte{10, 1, 2, 3})
	h.src.ch <- connectRecord(2, "outside", 2, []byte{192, 168, 0, 1})
	h.src.ch <- connectRecord(3, "inside6", 10, append(
		[]byte{0x20, 0x01, 0x0d, 0xb8}, make([]byte, 12)...))
	h.src.ch <- connectRecord(4, "outside6", 10, append(
		[]byte{0xfd, 0x00}, make([]byte, 14)...))
	// A non-connect event must pass regardless of the filter.
	h.src.ch <- exitRecord(5, "unrelated", 1)

	// The exit record is sent last and is in scope, so once three events have
	// landed every record above has been processed.
	waitFor(t, "the in-scope events", func() bool { return h.ring.Len() == 3 })

	events, _ := h.ring.Freeze()
	if len(events) != 3 {
		t.Fatalf("ring holds %d events, want 3: two of the five records are "+
			"outside every configured prefix", len(events))
	}
	got := map[string]bool{}
	for _, ev := range events {
		got[ev.Comm] = true
	}
	for _, want := range []string{"inside", "inside6", "unrelated"} {
		if !got[want] {
			t.Errorf("%q was filtered out but should have been recorded", want)
		}
	}
	for _, unwanted := range []string{"outside", "outside6"} {
		if got[unwanted] {
			t.Errorf("%q is outside every configured prefix but was recorded", unwanted)
		}
	}

	// Out of scope is not a drop: the operator asked for this.
	if n := h.drops.Total(); n != 0 {
		t.Errorf("drops = %d, want 0: a filtered event was never wanted, so "+
			"counting it would make the connect class look lossy for obeying "+
			"its configuration", n)
	}
}

// TestCIDRFilterKeepsUnclassifiableAddresses pins the deliberate direction of
// the doubt: an address the decoder could not render is kept, not discarded.
func TestCIDRFilterKeepsUnclassifiableAddresses(t *testing.T) {
	t.Parallel()
	h := newHarnessWithCIDRs(t, nil, nil, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	})

	// Address family 99 is one the decoder does not recognise, so it renders
	// DAddr as "".
	h.src.ch <- connectRecord(1, "unknownfam", 99, []byte{1, 2, 3, 4})
	waitFor(t, "the unclassifiable connect", func() bool { return h.ring.Len() == 1 })

	events, _ := h.ring.Freeze()
	if len(events) != 1 || events[0].Comm != "unknownfam" {
		t.Errorf("events = %+v, want the unclassifiable connect kept", events)
	}
}
