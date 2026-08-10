package event

import (
	"slices"
	"sync/atomic"
)

// Boundary names a place where an event can be lost. Drop accounting is
// load-bearing: a flight recorder that silently loses events is worse than
// none, so every boundary has a counter and every counter is surfaced in
// `wake status` and in every snapshot manifest.
type Boundary string

const (
	// BoundaryKernel counts events the BPF ring buffer could not accept
	// (reserve failed), as counted in kernel and read from a BPF map.
	BoundaryKernel Boundary = "kernel_ringbuf"
	// BoundaryDecode counts records the userspace decoder could not turn into
	// even a generic event. This should always be zero; if it is not, that is
	// a bug worth seeing.
	BoundaryDecode Boundary = "decode"
	// BoundaryRing counts events evicted from the userspace ring before a
	// snapshot could capture them (i.e. overwritten by newer events).
	BoundaryRing Boundary = "userspace_ring"
	// BoundaryWatch counts events not delivered to a `wake watch` client
	// because it could not keep up. Watch is a tuning aid and always loses
	// before the recorder does.
	BoundaryWatch Boundary = "watch_fanout"
)

// Boundaries lists every boundary in a stable reporting order. Like
// [Classes], it is an array so that len(Boundaries) is a compile-time
// constant.
var Boundaries = [...]Boundary{BoundaryKernel, BoundaryDecode, BoundaryRing, BoundaryWatch}

// Drops is a concurrent per-boundary, per-class drop counter.
//
// The zero value is ready to use. Counters only ever increase; a snapshot
// records absolute values so that a reader can difference two snapshots.
//
// The grid is sized directly from [Boundaries] and [Classes], so adding a
// boundary or a class needs no other edit here. Drop accounting is the one
// thing in this package that must not quietly go wrong, and a hand-maintained
// count beside the lists it was supposed to match is exactly how it would.
type Drops struct {
	counts [len(Boundaries)][len(Classes)]atomic.Uint64
}

// writeIndex locates the counter to record into for boundary b and class c.
//
// An unknown class folds into the generic class rather than being discarded,
// because losing the record of a loss is the one unacceptable failure here.
// An unknown boundary has no such fallback — there is no "generic boundary" —
// so it reports !ok and the update is dropped.
func writeIndex(b Boundary, c Class) (bi, ci int, ok bool) {
	bi = slices.Index(Boundaries[:], b)
	if bi < 0 {
		return 0, 0, false
	}
	ci = slices.Index(Classes[:], c)
	if ci < 0 {
		ci = slices.Index(Classes[:], ClassGeneric)
	}
	return bi, ci, true
}

// Add records n drops at boundary b for class c.
func (d *Drops) Add(b Boundary, c Class, n uint64) {
	if bi, ci, ok := writeIndex(b, c); ok {
		d.counts[bi][ci].Add(n)
	}
}

// Set overwrites the counter at boundary b for class c. Used for counters
// owned by the kernel, which are read rather than incremented.
func (d *Drops) Set(b Boundary, c Class, n uint64) {
	if bi, ci, ok := writeIndex(b, c); ok {
		d.counts[bi][ci].Store(n)
	}
}

// Get returns the counter at boundary b for class c. Unlike Add and Set, an
// unknown class reads as zero rather than folding into generic: a reader
// asking about a class that does not exist must not be handed some other
// class's count.
func (d *Drops) Get(b Boundary, c Class) uint64 {
	bi, ci := slices.Index(Boundaries[:], b), slices.Index(Classes[:], c)
	if bi < 0 || ci < 0 {
		return 0
	}
	return d.counts[bi][ci].Load()
}

// Total returns the sum of every counter.
func (d *Drops) Total() uint64 {
	var t uint64
	for bi := range d.counts {
		for ci := range d.counts[bi] {
			t += d.counts[bi][ci].Load()
		}
	}
	return t
}

// DropReport is the serialised form of Drops: boundary → class → count.
// Zero counters are included deliberately, so that a reader can tell
// "nothing was lost here" apart from "this boundary is not reported".
type DropReport map[string]map[string]uint64

// Report snapshots the counters into a serialisable form.
func (d *Drops) Report() DropReport {
	r := make(DropReport, len(Boundaries))
	for _, b := range Boundaries {
		m := make(map[string]uint64, len(Classes))
		for _, c := range Classes {
			m[string(c)] = d.Get(b, c)
		}
		r[string(b)] = m
	}
	return r
}
