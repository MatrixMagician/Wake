package snapshot

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/MatrixMagician/wake/internal/event"
)

// Writer builds and publishes snapshots. The zero value is not usable;
// construct one with NewWriter.
type Writer struct {
	root    string
	fs      FS
	sysInfo SystemInfoSource
	proc    ProcSource
	version string
	now     func() time.Time
}

// Option configures a Writer beyond its required arguments.
type Option func(*Writer)

// WithFS overrides the filesystem implementation. Defaults to OSFS.
func WithFS(fsys FS) Option { return func(w *Writer) { w.fs = fsys } }

// WithSystemInfoSource overrides how system.json is captured. Defaults to
// &OSSystemInfoSource{}.
func WithSystemInfoSource(s SystemInfoSource) Option {
	return func(w *Writer) { w.sysInfo = s }
}

// WithProcSource overrides how proc/ is captured. Defaults to
// &OSProcSource{}.
func WithProcSource(p ProcSource) Option { return func(w *Writer) { w.proc = p } }

// WithClock overrides the writer's notion of "now", used for the snapshot
// ID timestamp (when TriggerInfo.FiredAt is zero) and manifest.GeneratedAt.
// Defaults to time.Now. Tests use this for deterministic output.
func WithClock(now func() time.Time) Option { return func(w *Writer) { w.now = now } }

// NewWriter creates a Writer that publishes snapshots under root (typically
// /var/lib/wake/snapshots) and stamps manifests with wakeVersion
// (internal/version.Version — this package does not import internal/version
// to avoid a needless dependency edge for one string).
func NewWriter(root, wakeVersion string, opts ...Option) *Writer {
	w := &Writer{
		root:    root,
		fs:      OSFS{},
		sysInfo: &OSSystemInfoSource{},
		proc:    &OSProcSource{},
		version: wakeVersion,
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Result is what Write returns on success: enough for the caller to log,
// notify, or hand off to the ctl socket's response for `wake trigger`.
type Result struct {
	// ID is the snapshot's directory name.
	ID string
	// Path is the full path to the published snapshot directory.
	Path string
	// Manifest is the manifest that was written, for callers that want to
	// report event counts or drop totals without re-reading the file.
	Manifest Manifest
}

// Write builds a complete snapshot from in and publishes it under w's root.
// It is atomic: the whole snapshot is assembled in a hidden staging
// directory beside the final path, then published with a single rename, so
// a reader listing w's root never observes a partially written snapshot
// (see doc.go).
//
// Write does not itself enforce RetentionSettings; call Prune separately
// (typically right after a successful Write) so the two concerns —
// "did this snapshot get written correctly" and "do we still have room for
// it" — fail independently and are independently testable.
func (w *Writer) Write(in Input) (Result, error) {
	fired := in.Trigger.FiredAt
	if fired.IsZero() {
		fired = w.now()
	}
	id := snapshotID(fired, in.Trigger.Type)
	finalPath := w.root + "/" + id
	stagingPath := w.root + "/." + id + ".tmp"

	// A previous crashed write can leave a stale staging directory with
	// the same name (same trigger, same second); clear it first so this
	// attempt starts from a clean slate rather than merging with debris.
	if err := w.fs.RemoveAll(stagingPath); err != nil {
		return Result{}, fmt.Errorf("clear stale staging dir: %w", err)
	}
	if err := w.fs.MkdirAll(stagingPath, 0o700); err != nil {
		return Result{}, fmt.Errorf("create staging dir: %w", err)
	}
	// Best-effort cleanup on any failure path below: an aborted snapshot
	// should not leave a staging directory behind for the pruner to find
	// oddly named entries.
	publishedOK := false
	defer func() {
		if !publishedOK {
			_ = w.fs.RemoveAll(stagingPath)
		}
	}()

	events := make([]event.Event, len(in.Events))
	copy(events, in.Events)
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	eventCount, err := writeEventsJSONL(w.fs, stagingPath+"/events.jsonl.zst", events)
	if err != nil {
		return Result{}, fmt.Errorf("write events.jsonl.zst: %w", err)
	}

	sysInfo, err := w.sysInfo.Capture()
	if err != nil {
		return Result{}, fmt.Errorf("capture system.json: %w", err)
	}
	sysBytes, err := json.MarshalIndent(sysInfo, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("marshal system.json: %w", err)
	}
	if err := w.fs.WriteFile(stagingPath+"/system.json", sysBytes, 0o600); err != nil {
		return Result{}, fmt.Errorf("write system.json: %w", err)
	}

	var procSummary *ProcCaptureSummary
	if in.Trigger.PID != nil {
		procSummary, err = writeProcDir(w.fs, stagingPath+"/proc", *in.Trigger.PID, w.proc)
		if err != nil {
			return Result{}, fmt.Errorf("write proc/: %w", err)
		}
	}

	manifest := Manifest{
		SchemaVersion: event.SchemaVersion,
		ID:            id,
		WakeVersion:   w.version,
		GeneratedAt:   w.now().UTC(),
		Trigger:       in.Trigger,
		Host: HostInfo{
			Hostname:      sysInfo.Uname.Nodename,
			KernelRelease: sysInfo.Uname.Release,
			Machine:       sysInfo.Uname.Machine,
		},
		Window:      captureWindow(events),
		EventCount:  eventCount,
		EventCounts: countByClass(events),
		Drops:       in.Drops,
		ConfigHash:  in.ConfigHash,
		Proc:        procSummary,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("marshal manifest.json: %w", err)
	}
	if err := w.fs.WriteFile(stagingPath+"/manifest.json", manifestBytes, 0o600); err != nil {
		return Result{}, fmt.Errorf("write manifest.json: %w", err)
	}

	if err := w.fs.MkdirAll(w.root, 0o700); err != nil {
		return Result{}, fmt.Errorf("ensure snapshots root: %w", err)
	}
	if err := w.fs.Rename(stagingPath, finalPath); err != nil {
		return Result{}, fmt.Errorf("publish snapshot: %w", err)
	}
	publishedOK = true

	return Result{ID: id, Path: finalPath, Manifest: manifest}, nil
}

// writeEventsJSONL streams events, oldest first, as zstd-compressed JSONL to
// path, returning the number of events written. It shares
// event.Event.MarshalJSONLine with `wake watch` (SPEC.md §9 question 4) so
// live output and persisted output can never drift.
func writeEventsJSONL(fsys FS, path string, events []event.Event) (int, error) {
	f, err := fsys.CreateFile(path, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	zw, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return 0, fmt.Errorf("create zstd writer: %w", err)
	}

	for i := range events {
		line, err := events[i].MarshalJSONLine()
		if err != nil {
			return 0, fmt.Errorf("marshal event %d: %w", i, err)
		}
		if _, err := zw.Write(line); err != nil {
			return 0, fmt.Errorf("write event %d: %w", i, err)
		}
		if _, err := zw.Write([]byte{'\n'}); err != nil {
			return 0, fmt.Errorf("write event %d newline: %w", i, err)
		}
	}

	if err := zw.Close(); err != nil {
		return 0, fmt.Errorf("close zstd writer: %w", err)
	}
	return len(events), nil
}

// captureWindow returns the first and last event timestamps in events,
// which must already be sorted ascending by Timestamp. Both fields are nil
// for an empty slice.
func captureWindow(events []event.Event) CaptureWindow {
	if len(events) == 0 {
		return CaptureWindow{}
	}
	first := events[0].Timestamp
	last := events[len(events)-1].Timestamp
	return CaptureWindow{First: &first, Last: &last}
}

// countByClass returns the event count per class, including zero-count
// classes, mirroring event.DropReport's convention of making absence of
// loss explicit rather than implicit (internal/event/drops.go).
func countByClass(events []event.Event) map[string]uint64 {
	counts := make(map[string]uint64, len(event.Classes))
	for _, c := range event.Classes {
		counts[string(c)] = 0
	}
	for i := range events {
		counts[string(events[i].Class)]++
	}
	return counts
}
