package ring

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// mkEvent builds a minimal exec event of a given approximate size, n bytes
// heavier than the struct baseline, with a monotonically increasing
// timestamp so tests can assert time-window behaviour precisely.
func mkEvent(ts time.Time, extraBytes int) event.Event {
	e := event.Event{
		Timestamp: ts,
		Class:     event.ClassExec,
		PID:       1,
	}
	if extraBytes > 0 {
		e.Filename = string(make([]byte, extraBytes))
	}
	return e
}

func TestNewValidatesBounds(t *testing.T) {
	var d event.Drops
	cases := []struct {
		name    string
		age     time.Duration
		count   int
		bytes   int64
		drops   *event.Drops
		wantErr bool
	}{
		{"ok", time.Second, 10, 1024, &d, false},
		{"zero age", 0, 10, 1024, &d, true},
		{"negative age", -1, 10, 1024, &d, true},
		{"zero count", time.Second, 0, 1024, &d, true},
		{"zero bytes", time.Second, 10, 0, &d, true},
		{"nil drops", time.Second, 10, 1024, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.age, tc.count, tc.bytes, tc.drops)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New(%v,%v,%v) err=%v, wantErr=%v", tc.age, tc.count, tc.bytes, err, tc.wantErr)
			}
		})
	}
}

// TestCountBound verifies the count bound evicts oldest-first and never
// exceeds maxCount, with time and memory bounds set generously so only the
// count bound can bind.
func TestCountBound(t *testing.T) {
	var d event.Drops
	r, err := New(time.Hour, 5, 1<<20, &d)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	for i := 0; i < 12; i++ {
		r.Record(mkEvent(base.Add(time.Duration(i)*time.Millisecond), 0))
	}
	if got := r.Len(); got != 5 {
		t.Fatalf("Len() = %d, want 5", got)
	}
	frozen, _ := r.Freeze()
	if len(frozen) != 5 {
		t.Fatalf("frozen len = %d, want 5", len(frozen))
	}
	// The surviving events must be the 5 most recently recorded: PIDs carry
	// no ordering info here, so assert on timestamps instead — they must be
	// the last 5 of the 12 written, oldest-first.
	wantStart := base.Add(7 * time.Millisecond)
	if !frozen[0].Timestamp.Equal(wantStart) {
		t.Fatalf("frozen[0].Timestamp = %v, want %v", frozen[0].Timestamp, wantStart)
	}
	if got := d.Get(event.BoundaryRing, event.ClassExec); got != 7 {
		t.Fatalf("drops = %d, want 7", got)
	}
}

// TestTimeBound verifies the time-window bound evicts events older than
// maxAge relative to the newest recorded event's own timestamp.
func TestTimeBound(t *testing.T) {
	var d event.Drops
	r, err := New(10*time.Second, 1000, 1<<20, &d)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	r.Record(mkEvent(base, 0))                     // cutoff at write time: base-10s; survives that write
	r.Record(mkEvent(base.Add(4*time.Second), 0))  // cutoff: base-6s; base survives
	r.Record(mkEvent(base.Add(9*time.Second), 0))  // cutoff: base-1s; base survives
	r.Record(mkEvent(base.Add(11*time.Second), 0)) // cutoff: base+1s; base (only) now stale and evicted

	frozen, _ := r.Freeze()
	if len(frozen) != 3 {
		t.Fatalf("frozen len = %d, want 3 (got timestamps %v)", len(frozen), timestamps(frozen))
	}
	if !frozen[0].Timestamp.Equal(base.Add(4 * time.Second)) {
		t.Fatalf("frozen[0].Timestamp = %v, want base+4s", frozen[0].Timestamp)
	}
	if !frozen[len(frozen)-1].Timestamp.Equal(base.Add(11 * time.Second)) {
		t.Fatalf("frozen last Timestamp = %v, want base+11s", frozen[len(frozen)-1].Timestamp)
	}
	if got := d.Get(event.BoundaryRing, event.ClassExec); got != 1 {
		t.Fatalf("drops = %d, want 1", got)
	}
}

// TestMemoryBound verifies the memory budget evicts oldest events first, and
// that occupancy (Bytes) never exceeds the configured budget once at least
// one full-size event has been recorded.
func TestMemoryBound(t *testing.T) {
	var d event.Drops
	// Each event with 100 extra bytes costs roughly 320+100 = 420 bytes
	// (see event.Event.Size). Budget for ~3 at a time.
	budget := int64(1300)
	r, err := New(time.Hour, 1000, budget, &d)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	for i := 0; i < 10; i++ {
		e := mkEvent(base.Add(time.Duration(i)*time.Millisecond), 100)
		r.Record(e)
		if got := r.Bytes(); got > budget {
			t.Fatalf("after Record %d: Bytes() = %d exceeds budget %d", i, got, budget)
		}
	}
	if d.Get(event.BoundaryRing, event.ClassExec) == 0 {
		t.Fatal("expected evictions under memory pressure, got none")
	}
}

// TestAllThreeBoundsTogether checks that whichever bound is tightest wins,
// by tightening each in turn while holding the others loose.
func TestAllThreeBoundsTogether(t *testing.T) {
	var d event.Drops
	// Count is the tightest bound here.
	r, err := New(time.Hour, 3, 1<<20, &d)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	for i := 0; i < 20; i++ {
		r.Record(mkEvent(base.Add(time.Duration(i)*time.Millisecond), 0))
	}
	if got := r.Len(); got != 3 {
		t.Fatalf("count-bound: Len() = %d, want 3", got)
	}

	// Now memory is the tightest bound.
	var d2 event.Drops
	r2, err := New(time.Hour, 1000, 500, &d2) // ~1 event fits at a time
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		r2.Record(mkEvent(base.Add(time.Duration(i)*time.Millisecond), 50))
	}
	if got := r2.Bytes(); got > 500 {
		t.Fatalf("memory-bound: Bytes() = %d exceeds 500", got)
	}

	// Now time is the tightest bound.
	var d3 event.Drops
	r3, err := New(2*time.Millisecond, 1000, 1<<20, &d3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		r3.Record(mkEvent(base.Add(time.Duration(i)*time.Millisecond), 0))
	}
	frozen, _ := r3.Freeze()
	for _, e := range frozen {
		if e.Timestamp.Before(base.Add(17 * time.Millisecond)) {
			t.Fatalf("time-bound: found stale event %v", e.Timestamp)
		}
	}
}

// TestFreezeResetsAndContinuesRecording verifies Freeze swaps in a fresh
// buffer atomically, returns the frozen contents oldest-first, and that
// recording continues into the new buffer immediately — the "freezing is
// cheap, recording continues" invariant from SPEC.md §4.
func TestFreezeResetsAndContinuesRecording(t *testing.T) {
	var d event.Drops
	r, err := New(time.Hour, 100, 1<<20, &d)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	for i := 0; i < 5; i++ {
		r.Record(mkEvent(base.Add(time.Duration(i)*time.Millisecond), 0))
	}
	frozen, report := r.Freeze()
	if len(frozen) != 5 {
		t.Fatalf("frozen len = %d, want 5", len(frozen))
	}
	if !isOldestFirst(frozen) {
		t.Fatal("frozen contents not oldest-first")
	}
	if report[string(event.BoundaryRing)][string(event.ClassExec)] != 0 {
		t.Fatal("expected zero drops in report")
	}
	if r.Len() != 0 {
		t.Fatalf("Len() after Freeze = %d, want 0", r.Len())
	}

	// Recording after Freeze must land in the new, empty buffer without
	// touching the frozen slice.
	r.Record(mkEvent(base.Add(100*time.Millisecond), 0))
	if r.Len() != 1 {
		t.Fatalf("Len() after post-freeze Record = %d, want 1", r.Len())
	}
	if len(frozen) != 5 {
		t.Fatal("frozen slice mutated by post-freeze Record")
	}
}

// TestFreezeDropReportIsSnapshot verifies the returned DropReport reflects
// counts at the moment of freezing and is not mutated by later drops.
func TestFreezeDropReportIsSnapshot(t *testing.T) {
	var d event.Drops
	r, err := New(time.Hour, 2, 1<<20, &d)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	for i := 0; i < 5; i++ { // 5 recorded, cap 2 => 3 drops
		r.Record(mkEvent(base.Add(time.Duration(i)*time.Millisecond), 0))
	}
	_, report := r.Freeze()
	if report[string(event.BoundaryRing)][string(event.ClassExec)] != 3 {
		t.Fatalf("report drops = %d, want 3", report[string(event.BoundaryRing)][string(event.ClassExec)])
	}
	// Cause more drops after freezing; the earlier report must not change.
	for i := 0; i < 5; i++ {
		r.Record(mkEvent(base.Add(time.Duration(100+i)*time.Millisecond), 0))
	}
	if report[string(event.BoundaryRing)][string(event.ClassExec)] != 3 {
		t.Fatal("previously-returned DropReport mutated by later activity")
	}
}

// TestConcurrentRecordAndFreeze exercises Record and Freeze from many
// goroutines under -race, and checks every invariant holds on the union of
// everything ever frozen or left in the ring at the end: nothing exceeds the
// count/byte bounds instantaneously (best-effort, checked via drop
// accounting) and no event is duplicated or fabricated.
func TestConcurrentRecordAndFreeze(t *testing.T) {
	var d event.Drops
	r, err := New(50*time.Millisecond, 200, 1<<16, &d)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 8
	const perWriter = 500
	base := time.Now()

	var wg sync.WaitGroup
	seen := make(chan int, writers*perWriter)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				ts := base.Add(time.Duration(w*perWriter+i) * time.Microsecond)
				r.Record(mkEvent(ts, 8))
				seen <- 1
			}
		}(w)
	}

	// A concurrent freezer, racing with writers.
	var freezeWG sync.WaitGroup
	stopFreezing := make(chan struct{})
	freezeWG.Add(1)
	totalFrozen := 0
	var mu sync.Mutex
	go func() {
		defer freezeWG.Done()
		for {
			select {
			case <-stopFreezing:
				return
			default:
				frozen, _ := r.Freeze()
				mu.Lock()
				totalFrozen += len(frozen)
				mu.Unlock()
				time.Sleep(time.Millisecond)
			}
		}
	}()

	wg.Wait()
	close(stopFreezing)
	freezeWG.Wait()
	close(seen)

	frozen, _ := r.Freeze()
	mu.Lock()
	totalFrozen += len(frozen)
	mu.Unlock()

	sent := 0
	for range seen {
		sent++
	}
	dropped := d.Get(event.BoundaryRing, event.ClassExec)
	if uint64(totalFrozen)+dropped != uint64(sent) {
		t.Fatalf("accounting mismatch: frozen=%d dropped=%d sent=%d", totalFrozen, dropped, sent)
	}
}

// TestPropertyEvictionOrdering runs a seeded random sequence of Record calls
// against varying bounds and asserts, after every operation, that: (1) the
// live contents are monotonically increasing in timestamp (oldest gone
// first, never reordered), (2) the count never exceeds maxCount, (3) the
// memory usage never exceeds maxBytes, and (4) no event older than the time
// window (relative to the newest recorded event) survives.
func TestPropertyEvictionOrdering(t *testing.T) {
	const seed = 1
	rnd := rand.New(rand.NewSource(seed))

	for trial := 0; trial < 20; trial++ {
		maxCount := 1 + rnd.Intn(20)
		maxBytes := int64(400 + rnd.Intn(4000))
		maxAge := time.Duration(1+rnd.Intn(50)) * time.Millisecond

		var d event.Drops
		r, err := New(maxAge, maxCount, maxBytes, &d)
		if err != nil {
			t.Fatal(err)
		}

		base := time.Now()
		var lastTS time.Time
		n := 200
		for i := 0; i < n; i++ {
			ts := base.Add(time.Duration(i) * time.Millisecond)
			extra := rnd.Intn(300)
			r.Record(mkEvent(ts, extra))
			lastTS = ts

			r.mu.Lock()
			buf := r.active
			live := buf.entries[buf.front:]

			if len(live) > maxCount {
				r.mu.Unlock()
				t.Fatalf("trial %d step %d: live count %d exceeds maxCount %d", trial, i, len(live), maxCount)
			}
			if buf.bytes > maxBytes && len(live) > 1 {
				// A single oversized event alone may exceed the budget
				// (unavoidable), but with >1 event present the budget must
				// hold.
				r.mu.Unlock()
				t.Fatalf("trial %d step %d: bytes %d exceeds maxBytes %d with %d events live", trial, i, buf.bytes, maxBytes, len(live))
			}
			cutoff := lastTS.Add(-maxAge)
			var prev time.Time
			for j, e := range live {
				if e.Timestamp.Before(cutoff) {
					r.mu.Unlock()
					t.Fatalf("trial %d step %d: stale event at %v survives (cutoff %v)", trial, i, e.Timestamp, cutoff)
				}
				if j > 0 && e.Timestamp.Before(prev) {
					r.mu.Unlock()
					t.Fatalf("trial %d step %d: timestamps not monotonic: %v after %v", trial, i, e.Timestamp, prev)
				}
				prev = e.Timestamp
			}
			r.mu.Unlock()
		}
	}
}

func isOldestFirst(es []event.Event) bool {
	for i := 1; i < len(es); i++ {
		if es[i].Timestamp.Before(es[i-1].Timestamp) {
			return false
		}
	}
	return true
}

func timestamps(es []event.Event) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = fmt.Sprintf("%v", e.Timestamp)
	}
	return out
}

// TestSpanReportsTheLiveWindow covers `wake status`'s "how much history am I
// looking at?" line, which reported nothing at all until Span existed.
func TestSpanReportsTheLiveWindow(t *testing.T) {
	t.Parallel()
	var drops event.Drops
	r, err := New(time.Hour, 100, 1<<20, &drops)
	if err != nil {
		t.Fatal(err)
	}

	if oldest, newest := r.Span(); oldest != nil || newest != nil {
		t.Errorf("empty ring reported a span of %v..%v, want two nils", oldest, newest)
	}

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		r.Record(event.Event{
			Class:     event.ClassExec,
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}

	oldest, newest := r.Span()
	if oldest == nil || newest == nil {
		t.Fatalf("populated ring reported %v..%v, want both set", oldest, newest)
	}
	if !oldest.Equal(base) {
		t.Errorf("oldest = %v, want %v", oldest, base)
	}
	if want := base.Add(4 * time.Second); !newest.Equal(want) {
		t.Errorf("newest = %v, want %v", newest, want)
	}
}

// TestSpanFollowsEviction pins that the reported window shrinks from the front
// as events are evicted: a span covering events the ring no longer holds would
// overstate how much history a snapshot would contain.
func TestSpanFollowsEviction(t *testing.T) {
	t.Parallel()
	var drops event.Drops
	r, err := New(time.Hour, 3, 1<<20, &drops)
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		r.Record(event.Event{
			Class:     event.ClassExec,
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}

	oldest, _ := r.Span()
	if oldest == nil {
		t.Fatal("span is empty after recording")
	}
	// Count bound is 3, so the first two events are gone.
	if want := base.Add(2 * time.Second); !oldest.Equal(want) {
		t.Errorf("oldest = %v, want %v: the span must not name an evicted event",
			oldest, want)
	}
}
