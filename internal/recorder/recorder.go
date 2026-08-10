// Package recorder is the daemon's spine: it pulls raw records from a Source,
// decodes them, feeds the enrichment cache, records them in the ring, fans
// them out to watchers, and evaluates triggers.
//
// It depends on interfaces rather than concrete packages wherever a fake makes
// a test cheaper, which is why the whole daemon loop can be exercised with no
// kernel, no systemd and no filesystem.
package recorder

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/MatrixMagician/wake/internal/decode"
	"github.com/MatrixMagician/wake/internal/event"
	"github.com/MatrixMagician/wake/internal/loader"
	"github.com/MatrixMagician/wake/internal/ring"
	"github.com/MatrixMagician/wake/internal/trigger"
)

// Enricher attributes an event to a process, unit and container. The recorder
// only needs these two methods, so it asks for only these two.
type Enricher interface {
	Observe(ev event.Event)
	Resolve(ev *event.Event)
}

// Redactor masks configured patterns before an event is serialised or shown.
type Redactor interface {
	Redact(ev *event.Event)
}

// Recorder owns the hot path.
type Recorder struct {
	src      loader.Source
	dec      *decode.Decoder
	ring     *ring.Ring
	enrich   Enricher
	redact   Redactor
	triggers *trigger.Engine
	drops    *event.Drops
	log      *slog.Logger

	kernelDropInterval time.Duration

	mu       sync.Mutex
	watchers map[int]*watcher
	nextID   int
}

// Options configures a Recorder. Everything is required except the redactor,
// which may be nil when no patterns are configured.
type Options struct {
	Source   loader.Source
	Decoder  *decode.Decoder
	Ring     *ring.Ring
	Enricher Enricher
	Redactor Redactor
	Triggers *trigger.Engine
	Drops    *event.Drops
	Logger   *slog.Logger

	// KernelDropInterval is how often the BPF-side counters are copied into
	// the shared report. Zero means the default. It is configurable chiefly so
	// that tests need not wait real seconds to assert on drop accounting.
	KernelDropInterval time.Duration
}

// DefaultKernelDropInterval is frequent enough that a snapshot taken at any
// moment has near-current kernel drop counts, and rare enough that the map
// lookups are free in comparison to the event rate.
const DefaultKernelDropInterval = 2 * time.Second

// New constructs a Recorder.
func New(o Options) *Recorder {
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	interval := o.KernelDropInterval
	if interval <= 0 {
		interval = DefaultKernelDropInterval
	}
	return &Recorder{
		kernelDropInterval: interval,
		src:                o.Source, dec: o.Decoder, ring: o.Ring,
		enrich: o.Enricher, redact: o.Redactor, triggers: o.Triggers,
		drops: o.Drops, log: log,
		watchers: make(map[int]*watcher),
	}
}

// Run pumps events until the context is cancelled or the source closes.
//
// Redaction happens here, on the way in, rather than at snapshot time. That is
// the stronger guarantee: a secret that never enters the ring cannot leak
// through a watch stream either, and there is only one code path to get wrong.
func (r *Recorder) Run(ctx context.Context) error {
	records := r.src.Records()
	kernelDrops := time.NewTicker(r.kernelDropInterval)
	defer kernelDrops.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-kernelDrops.C:
			r.syncKernelDrops()

		case rec, ok := <-records:
			if !ok {
				r.syncKernelDrops()
				return nil
			}
			ev := r.dec.Decode(rec.Raw)

			if ev.Class == event.ClassGeneric && ev.DecodeError != "" {
				// Not a drop: the event is kept. But it is worth knowing that
				// the kernel is producing something we do not understand.
				r.log.Debug("record decoded generically",
					"reason", ev.DecodeError, "kind", ev.RawKind)
			}

			r.enrich.Observe(ev)
			r.enrich.Resolve(&ev)
			if r.redact != nil {
				r.redact.Redact(&ev)
			}

			r.ring.Record(ev)
			r.fanOut(ev)
			r.triggers.Observe(&ev)
		}
	}
}

// syncKernelDrops copies the BPF-side counters into the shared drop report, so
// that a snapshot taken at any moment carries kernel losses as well as
// userspace ones.
func (r *Recorder) syncKernelDrops() {
	counts, err := r.src.KernelDrops()
	if err != nil {
		r.log.Warn("could not read kernel drop counters", "err", err)
		return
	}
	for class, n := range counts {
		r.drops.Set(event.BoundaryKernel, event.Class(class), n)
	}
}

// Freeze swaps the ring and returns its contents. It is O(1) on the hot path;
// serialising the result happens in the snapshot writer, so recording
// continues throughout (SPEC.md §4, "Freezing is cheap").
func (r *Recorder) Freeze() ([]event.Event, event.DropReport) {
	return r.ring.Freeze()
}

// watcher is one `wake watch` client.
type watcher struct {
	ch      chan event.Event
	classes map[string]bool
	unit    string
}

// Subscribe registers a watch stream. Watch is explicitly a tuning aid: it
// loses events before the recorder does, and every loss is counted at
// event.BoundaryWatch rather than hidden.
func (r *Recorder) Subscribe(classes []string, unit string) (<-chan event.Event, func()) {
	w := &watcher{ch: make(chan event.Event, 256), unit: unit}
	if len(classes) > 0 {
		w.classes = make(map[string]bool, len(classes))
		for _, c := range classes {
			w.classes[c] = true
		}
	}

	r.mu.Lock()
	id := r.nextID
	r.nextID++
	r.watchers[id] = w
	r.mu.Unlock()

	return w.ch, func() {
		r.mu.Lock()
		if _, ok := r.watchers[id]; ok {
			delete(r.watchers, id)
			close(w.ch)
		}
		r.mu.Unlock()
	}
}

func (r *Recorder) fanOut(ev event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, w := range r.watchers {
		if w.classes != nil && !w.classes[string(ev.Class)] {
			continue
		}
		if w.unit != "" && ev.Unit != w.unit {
			continue
		}
		select {
		case w.ch <- ev:
		default:
			// The watcher cannot keep up. Losing its events is correct; losing
			// them silently is not.
			r.drops.Add(event.BoundaryWatch, ev.Class, 1)
		}
	}
}
