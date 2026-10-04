// Package ring implements Wake's bounded in-memory event ring: the only
// steady-state memory consumer in the daemon (CLAUDE.md, "load-bearing
// invariants"). See SPEC.md §2 goal 3 and §4 ("Freezing is cheap").
//
// The ring is bounded simultaneously by a time window, an event count, and a
// memory budget; whichever binds first evicts the oldest event. Every such
// eviction is a genuine drop — the event existed and is gone before any
// snapshot could see it — so it is counted at event.BoundaryRing for its
// class, per CONTEXT.md's definition of Drop.
package ring

import (
	"errors"
	"sync"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// Ring is a bounded, concurrency-safe FIFO of event.Event. The zero value is
// not usable; construct with New.
//
// Internally the live buffer is a plain append-only []event.Event with a
// "front" index marking the oldest live element, rather than a fixed-size
// circular array. That choice is what makes Freeze O(1): the frozen buffer's
// tail slice (buf.entries[buf.front:]) is *already* the ordered, oldest-first
// contents the caller wants, so Freeze need not walk or copy a single event —
// it only swaps a pointer and reads the (small, fixed-size) drop counters.
// The cost of maintaining that ordered slice — appending and occasionally
// compacting away consumed front elements — is paid incrementally by Record,
// which is where the SPEC explicitly allows amortised cost.
type Ring struct {
	mu       sync.Mutex
	active   *buffer
	maxAge   time.Duration
	maxCount int
	maxBytes int64
	drops    *event.Drops
}

// buffer holds the events currently being accumulated. entries[front:] is the
// live, oldest-first window; entries[:front] is dead space retained only
// until the next compaction reclaims it.
type buffer struct {
	entries []event.Event
	front   int
	bytes   int64
}

func (b *buffer) count() int { return len(b.entries) - b.front }

// compactThreshold bounds how much dead space (already-evicted entries at the
// front of the backing array) a buffer tolerates before Record pays to
// reclaim it. Chosen so compaction is rare relative to append, not so large
// that a long-lived low-throughput ring pins a big backing array forever.
const compactThreshold = 256

// New constructs a Ring bounded by maxAge, maxCount and maxBytes
// simultaneously — whichever binds first wins, per SPEC.md §2 goal 3. drops
// must be non-nil: every eviction is recorded against it at
// event.BoundaryRing, keyed by the evicted event's class.
//
// All three bounds must be positive. To exercise one bound in isolation
// (as the property tests do), set the other two generously large rather than
// passing a zero/"unbounded" sentinel — a real Wake config always sets all
// three, so Ring never needs to represent "no bound".
func New(maxAge time.Duration, maxCount int, maxBytes int64, drops *event.Drops) (*Ring, error) {
	switch {
	case maxAge <= 0:
		return nil, errors.New("ring: maxAge must be positive")
	case maxCount <= 0:
		return nil, errors.New("ring: maxCount must be positive")
	case maxBytes <= 0:
		return nil, errors.New("ring: maxBytes must be positive")
	case drops == nil:
		return nil, errors.New("ring: drops must not be nil")
	}
	return &Ring{
		active:   &buffer{},
		maxAge:   maxAge,
		maxCount: maxCount,
		maxBytes: maxBytes,
		drops:    drops,
	}, nil
}

// Record appends e to the ring, evicting the oldest events first until the
// time, count and memory bounds all hold. e is copied by value (Event is a
// flat struct; its slice/string fields are shared, not deep-copied, matching
// the rest of the codebase's treatment of Event as an immutable record once
// decoded).
//
// The time bound is evaluated relative to e.Timestamp rather than the wall
// clock: the ring is a window of *recorded* time, and using the newest
// event's own timestamp as "now" keeps eviction deterministic under test and
// correct even if the daemon's wall clock and event timestamps drift.
func (r *Ring) Record(e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	sz := e.Size()
	buf := r.active
	cutoff := e.Timestamp.Add(-r.maxAge)

	for buf.count() > 0 {
		oldest := &buf.entries[buf.front]
		over := buf.count() >= r.maxCount ||
			buf.bytes+int64(sz) > r.maxBytes ||
			oldest.Timestamp.Before(cutoff)
		if !over {
			break
		}
		r.evictOldest(buf)
	}

	buf.entries = append(buf.entries, e)
	buf.bytes += int64(sz)
	r.maybeCompact(buf)
}

// evictOldest drops buf's front-most event, counting it as a real drop
// (event.BoundaryRing) and zeroing its slot so the evicted event's own
// heap-allocated fields (Argv, Raw, Ancestors, ...) can be collected even
// though the backing array survives until the next compaction.
func (r *Ring) evictOldest(buf *buffer) {
	oldest := &buf.entries[buf.front]
	r.drops.Add(event.BoundaryRing, oldest.Class, 1)
	buf.bytes -= int64(oldest.Size())
	buf.entries[buf.front] = event.Event{}
	buf.front++
}

// maybeCompact reclaims dead space at the front of buf's backing array once
// it has grown past compactThreshold and is at least half the live window,
// so a bursty-then-quiet ring doesn't pin an ever-growing array purely from
// historical front advancement.
func (r *Ring) maybeCompact(buf *buffer) {
	if buf.front < compactThreshold || buf.front*2 < len(buf.entries) {
		return
	}
	n := copy(buf.entries, buf.entries[buf.front:])
	for i := n; i < len(buf.entries); i++ {
		buf.entries[i] = event.Event{} // release references before truncating
	}
	buf.entries = buf.entries[:n]
	buf.front = 0
}

// Freeze atomically swaps the active buffer for a fresh, empty one and
// returns the frozen buffer's contents (oldest-first) together with a
// snapshot of the drop report at the moment of freezing.
//
// This is the O(1) operation SPEC.md §4 calls "freezing is cheap": the
// critical section only swaps a pointer and copies event.Drops' fixed-size
// counter grid, never touches the frozen events themselves. Record on the
// new, empty buffer proceeds immediately and concurrently; nothing here
// blocks on however many events happened to be in the ring.
//
// The returned slice aliases the frozen buffer's backing array rather than
// copying it — safe because that buffer is never written to again (the Ring
// now records into a different one) — so callers must treat it as read-only.
func (r *Ring) Freeze() ([]event.Event, event.DropReport) {
	r.mu.Lock()
	old := r.active
	r.active = &buffer{}
	report := r.drops.Report()
	r.mu.Unlock()

	return old.entries[old.front:], report
}

// Len reports the number of events currently held. Intended for `wake
// status` (ring occupancy) rather than the hot path.
func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active.count()
}

// Span reports the timestamps of the oldest and newest events currently held,
// or two nils when the ring is empty. It answers the first question an
// operator asks during an incident: how much history would a snapshot taken
// right now actually contain?
//
// The bounds are read from the ends of the live window rather than by scanning
// for the true minimum and maximum, which keeps this O(1) on a ring that may
// hold hundreds of thousands of events. That is the same assumption eviction
// already makes — it treats the front entry as the oldest — so the two cannot
// disagree. The snapshot writer still sorts by timestamp, so a slightly
// out-of-order arrival affects this display and nothing else.
func (r *Ring) Span() (oldest, newest *time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active.count() == 0 {
		return nil, nil
	}
	o := r.active.entries[r.active.front].Timestamp
	n := r.active.entries[len(r.active.entries)-1].Timestamp
	return &o, &n
}

// Bytes reports the estimated memory currently held, per event.Event.Size().
// Intended for `wake status` alongside Len.
func (r *Ring) Bytes() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active.bytes
}
