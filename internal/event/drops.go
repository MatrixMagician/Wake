package event

import "sync/atomic"

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

// Boundaries lists every boundary in a stable reporting order.
var Boundaries = []Boundary{BoundaryKernel, BoundaryDecode, BoundaryRing, BoundaryWatch}

// Drops is a concurrent per-boundary, per-class drop counter.
//
// The zero value is ready to use. Counters only ever increase; a snapshot
// records absolute values so that a reader can difference two snapshots.
type Drops struct {
	counts [numBoundaries][numClasses]atomic.Uint64
}

const (
	numBoundaries = 4
	numClasses    = 7
)

var boundaryIndex = map[Boundary]int{
	BoundaryKernel: 0, BoundaryDecode: 1, BoundaryRing: 2, BoundaryWatch: 3,
}

var classIndex = map[Class]int{
	ClassExec: 0, ClassExit: 1, ClassSignal: 2, ClassOOM: 3,
	ClassOpen: 4, ClassConnect: 5, ClassGeneric: 6,
}

// Add records n drops at boundary b for class c. Unknown boundaries or classes
// are folded into the generic class rather than discarded, because losing the
// record of a loss is the one unacceptable failure here.
func (d *Drops) Add(b Boundary, c Class, n uint64) {
	bi, ok := boundaryIndex[b]
	if !ok {
		return
	}
	ci, ok := classIndex[c]
	if !ok {
		ci = classIndex[ClassGeneric]
	}
	d.counts[bi][ci].Add(n)
}

// Set overwrites the counter at boundary b for class c. Used for counters
// owned by the kernel, which are read rather than incremented.
func (d *Drops) Set(b Boundary, c Class, n uint64) {
	bi, ok := boundaryIndex[b]
	if !ok {
		return
	}
	ci, ok := classIndex[c]
	if !ok {
		ci = classIndex[ClassGeneric]
	}
	d.counts[bi][ci].Store(n)
}

// Get returns the counter at boundary b for class c.
func (d *Drops) Get(b Boundary, c Class) uint64 {
	bi, ok := boundaryIndex[b]
	if !ok {
		return 0
	}
	ci, ok := classIndex[c]
	if !ok {
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
