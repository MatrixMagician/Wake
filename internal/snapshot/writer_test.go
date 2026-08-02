package snapshot

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/MatrixMagician/wake/internal/event"
)

// fakeSystemInfoSource returns fixed data, so writer tests never touch the
// real /proc.
type fakeSystemInfoSource struct {
	info SystemInfo
	err  error
}

func (f fakeSystemInfoSource) Capture() (SystemInfo, error) { return f.info, f.err }

// fakeProcSource returns canned scrape results keyed by pid, so writer
// tests never touch the real /proc or require the process to exist.
type fakeProcSource struct {
	byPID map[int32]fakeProcResult
}

type fakeProcResult struct {
	files map[string][]byte
	fds   map[string]string
	found bool
	err   error
}

func (f fakeProcSource) Scrape(pid int32) (map[string][]byte, map[string]string, bool, error) {
	r, ok := f.byPID[pid]
	if !ok {
		return nil, nil, false, nil
	}
	return r.files, r.fds, r.found, r.err
}

func testUname() Uname {
	return Uname{Sysname: "Linux", Nodename: "test-host", Release: "6.10.0-test", Version: "#1 SMP", Machine: "x86_64"}
}

func newTestWriter(t *testing.T, root string, opts ...Option) *Writer {
	t.Helper()
	defaultOpts := []Option{
		WithSystemInfoSource(fakeSystemInfoSource{info: SystemInfo{Uname: testUname(), Uptime: 12345}}),
		WithProcSource(fakeProcSource{}),
		WithClock(func() time.Time { return time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC) }),
	}
	return NewWriter(root, "v0.0.0-test", append(defaultOpts, opts...)...)
}

func mustEvent(class event.Class, ts time.Time) event.Event {
	return event.Event{Timestamp: ts, Class: class, PID: 100, UID: 1000}
}

func TestWrite_BasicShapeAndAtomicity(t *testing.T) {
	root := t.TempDir()
	w := newTestWriter(t, root)

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	in := Input{
		Events: []event.Event{
			mustEvent(event.ClassExit, base.Add(3*time.Second)),
			mustEvent(event.ClassExec, base),
			mustEvent(event.ClassOpen, base.Add(1*time.Second)),
		},
		Drops:      event.DropReport{},
		Trigger:    TriggerInfo{Type: "manual", Reason: "test", FiredAt: base},
		ConfigHash: "deadbeef",
	}

	result, err := w.Write(in)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	wantID := "20260802T115900Z-manual"
	if result.ID != wantID {
		t.Errorf("ID = %q, want %q", result.ID, wantID)
	}

	// No staging directories left behind.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir root: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("root has %d entries, want 1: %v", len(entries), entries)
	}
	if entries[0].Name() != wantID {
		t.Errorf("root entry = %q, want %q", entries[0].Name(), wantID)
	}

	// manifest.json exists and parses.
	manifestBytes, err := os.ReadFile(filepath.Join(root, wantID, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		t.Fatalf("unmarshal manifest.json: %v", err)
	}
	if m.EventCount != 3 {
		t.Errorf("EventCount = %d, want 3", m.EventCount)
	}
	if m.SchemaVersion != event.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", m.SchemaVersion, event.SchemaVersion)
	}
	if m.Host.Hostname != "test-host" {
		t.Errorf("Host.Hostname = %q, want test-host", m.Host.Hostname)
	}
	if m.Window.First == nil || !m.Window.First.Equal(base) {
		t.Errorf("Window.First = %v, want %v", m.Window.First, base)
	}
	if m.Window.Last == nil || !m.Window.Last.Equal(base.Add(3*time.Second)) {
		t.Errorf("Window.Last = %v, want %v", m.Window.Last, base.Add(3*time.Second))
	}
	if m.EventCounts["exec"] != 1 || m.EventCounts["exit"] != 1 || m.EventCounts["open"] != 1 {
		t.Errorf("EventCounts = %+v, want exec/exit/open = 1 each", m.EventCounts)
	}
	if m.EventCounts["oom"] != 0 {
		t.Errorf("EventCounts[oom] = %d, want 0 (zero counts must be explicit)", m.EventCounts["oom"])
	}
	if m.ConfigHash != "deadbeef" {
		t.Errorf("ConfigHash = %q, want deadbeef", m.ConfigHash)
	}

	// system.json exists and parses.
	sysBytes, err := os.ReadFile(filepath.Join(root, wantID, "system.json"))
	if err != nil {
		t.Fatalf("read system.json: %v", err)
	}
	var sys SystemInfo
	if err := json.Unmarshal(sysBytes, &sys); err != nil {
		t.Fatalf("unmarshal system.json: %v", err)
	}
	if sys.Uname.Machine != "x86_64" {
		t.Errorf("system.json uname.machine = %q, want x86_64", sys.Uname.Machine)
	}

	// events.jsonl.zst decompresses to 3 lines, oldest first.
	events := readEventsFixture(t, filepath.Join(root, wantID, "events.jsonl.zst"))
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	wantOrder := []event.Class{event.ClassExec, event.ClassOpen, event.ClassExit}
	for i, c := range wantOrder {
		if events[i].Class != c {
			t.Errorf("event[%d].Class = %q, want %q", i, events[i].Class, c)
		}
	}
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Before(events[i-1].Timestamp) {
			t.Errorf("events not sorted ascending at index %d", i)
		}
	}
}

func TestWrite_InputEventsSliceNotMutated(t *testing.T) {
	root := t.TempDir()
	w := newTestWriter(t, root)

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	original := []event.Event{
		mustEvent(event.ClassExit, base.Add(3*time.Second)),
		mustEvent(event.ClassExec, base),
	}
	// Keep a copy of the original order to compare against after Write.
	wantFirstClass := original[0].Class

	_, err := w.Write(Input{Events: original, Trigger: TriggerInfo{Type: "manual", FiredAt: base}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if original[0].Class != wantFirstClass {
		t.Errorf("caller's Events slice was mutated: [0].Class = %q, want %q", original[0].Class, wantFirstClass)
	}
}

func TestWrite_EmptyEvents(t *testing.T) {
	root := t.TempDir()
	w := newTestWriter(t, root)

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	result, err := w.Write(Input{Trigger: TriggerInfo{Type: "manual", FiredAt: base}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if result.Manifest.EventCount != 0 {
		t.Errorf("EventCount = %d, want 0", result.Manifest.EventCount)
	}
	if result.Manifest.Window.First != nil || result.Manifest.Window.Last != nil {
		t.Errorf("Window = %+v, want both nil for empty events", result.Manifest.Window)
	}
	events := readEventsFixture(t, filepath.Join(result.Path, "events.jsonl.zst"))
	if len(events) != 0 {
		t.Errorf("got %d events, want 0", len(events))
	}
}

func TestWrite_DropsCopiedVerbatim(t *testing.T) {
	root := t.TempDir()
	w := newTestWriter(t, root)

	var d event.Drops
	d.Add(event.BoundaryRing, event.ClassExec, 5)
	d.Set(event.BoundaryKernel, event.ClassOOM, 2)
	report := d.Report()

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	result, err := w.Write(Input{Drops: report, Trigger: TriggerInfo{Type: "manual", FiredAt: base}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if result.Manifest.Drops[string(event.BoundaryRing)][string(event.ClassExec)] != 5 {
		t.Errorf("drop report not preserved: %+v", result.Manifest.Drops)
	}
	if result.Manifest.Drops[string(event.BoundaryKernel)][string(event.ClassOOM)] != 2 {
		t.Errorf("drop report not preserved: %+v", result.Manifest.Drops)
	}
	// Zero counters for every other boundary/class must still be present.
	if _, ok := result.Manifest.Drops[string(event.BoundaryWatch)][string(event.ClassConnect)]; !ok {
		t.Errorf("zero drop counter missing from report: %+v", result.Manifest.Drops)
	}
}

func TestWrite_StagingDirCleanedUpOnFailure(t *testing.T) {
	root := t.TempDir()
	w := newTestWriter(t, root, WithSystemInfoSource(fakeSystemInfoSource{err: io.ErrUnexpectedEOF}))

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	_, err := w.Write(Input{Trigger: TriggerInfo{Type: "manual", FiredAt: base}})
	if err == nil {
		t.Fatal("expected an error from a failing SystemInfoSource")
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir root: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("root has leftover entries after failed write: %v", entries)
	}
}

func TestWrite_StaleStagingDirIsCleared(t *testing.T) {
	root := t.TempDir()
	w := newTestWriter(t, root)

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	id := snapshotID(base, "manual")
	staging := filepath.Join(root, "."+id+".tmp")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "junk.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := w.Write(Input{Trigger: TriggerInfo{Type: "manual", FiredAt: base}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.Path, "junk.txt")); !os.IsNotExist(err) {
		t.Errorf("stale staging content leaked into published snapshot")
	}
}

func TestWrite_TriggerTypeSanitisedInID(t *testing.T) {
	root := t.TempDir()
	w := newTestWriter(t, root)

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	result, err := w.Write(Input{Trigger: TriggerInfo{Type: "systemd-unit-failed", FiredAt: base}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.HasSuffix(result.ID, "-systemd-unit-failed") {
		t.Errorf("ID = %q, want suffix -systemd-unit-failed", result.ID)
	}
}

func TestWrite_ProcScrapeFound(t *testing.T) {
	root := t.TempDir()
	pid := int32(4321)
	proc := fakeProcSource{byPID: map[int32]fakeProcResult{
		pid: {
			found: true,
			files: map[string][]byte{
				"status": []byte("Name:\tsmtpd\nPid:\t4321\n"),
				"cgroup": []byte("0::/system.slice/mstr.service\n"),
			},
			fds: map[string]string{"0": "/dev/null", "3": "socket:[12345]"},
		},
	}}
	w := newTestWriter(t, root, WithProcSource(proc))

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	result, err := w.Write(Input{Trigger: TriggerInfo{Type: "watched-process", PID: &pid, FiredAt: base}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if result.Manifest.Proc == nil || !result.Manifest.Proc.Found {
		t.Fatalf("Manifest.Proc = %+v, want Found=true", result.Manifest.Proc)
	}
	statusBytes, err := os.ReadFile(filepath.Join(result.Path, "proc", "status"))
	if err != nil {
		t.Fatalf("read proc/status: %v", err)
	}
	if !strings.Contains(string(statusBytes), "smtpd") {
		t.Errorf("proc/status = %q, want to contain smtpd", statusBytes)
	}
	fdListing, err := os.ReadFile(filepath.Join(result.Path, "proc", "fd_listing.txt"))
	if err != nil {
		t.Fatalf("read proc/fd_listing.txt: %v", err)
	}
	if !strings.Contains(string(fdListing), "/dev/null") {
		t.Errorf("fd_listing.txt = %q, want to contain /dev/null", fdListing)
	}
}

func TestWrite_ProcScrapeNotFound(t *testing.T) {
	root := t.TempDir()
	pid := int32(9999)
	w := newTestWriter(t, root, WithProcSource(fakeProcSource{}))

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	result, err := w.Write(Input{Trigger: TriggerInfo{Type: "watched-process", PID: &pid, FiredAt: base}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if result.Manifest.Proc == nil || result.Manifest.Proc.Found {
		t.Fatalf("Manifest.Proc = %+v, want Found=false", result.Manifest.Proc)
	}
	if _, err := os.Stat(filepath.Join(result.Path, "proc")); !os.IsNotExist(err) {
		t.Errorf("proc/ directory should not exist when the process was not found")
	}
}

func TestWrite_NoTriggerPID_NoProcCapture(t *testing.T) {
	root := t.TempDir()
	w := newTestWriter(t, root)

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	result, err := w.Write(Input{Trigger: TriggerInfo{Type: "manual", FiredAt: base}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if result.Manifest.Proc != nil {
		t.Errorf("Manifest.Proc = %+v, want nil when no trigger PID", result.Manifest.Proc)
	}
}

func TestWrite_SnapshotDirsAreMode0700(t *testing.T) {
	root := t.TempDir()
	w := newTestWriter(t, root)

	base := time.Date(2026, 8, 2, 11, 59, 0, 0, time.UTC)
	result, err := w.Write(Input{Trigger: TriggerInfo{Type: "manual", FiredAt: base}})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("snapshot dir mode = %v, want 0700", info.Mode().Perm())
	}
}

func TestWrite_UsesFiredAtWhenSet_ClockOtherwise(t *testing.T) {
	root := t.TempDir()
	clockTime := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	w := newTestWriter(t, root, WithClock(func() time.Time { return clockTime }))

	result, err := w.Write(Input{Trigger: TriggerInfo{Type: "manual"}}) // FiredAt zero
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := snapshotID(clockTime, "manual")
	if result.ID != want {
		t.Errorf("ID = %q, want %q (fall back to clock when FiredAt is zero)", result.ID, want)
	}
}

// readEventsFixture decompresses and parses a written events.jsonl.zst file.
func readEventsFixture(t *testing.T, path string) []event.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatalf("zstd.NewReader: %v", err)
	}
	defer zr.Close()

	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	var events []event.Event
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e event.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("unmarshal line %q: %v", line, err)
		}
		events = append(events, e)
	}
	return events
}
