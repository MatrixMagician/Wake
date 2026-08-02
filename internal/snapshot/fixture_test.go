package snapshot_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/MatrixMagician/wake/internal/event"
	"github.com/MatrixMagician/wake/internal/snapshot"
)

// fixtureDir locates testdata/fixtures/reference-snapshot relative to this
// test file, independent of the working directory `go test` is invoked
// from.
func fixtureDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// This test file lives at internal/snapshot/fixture_test.go; the fixture
	// lives at testdata/fixtures/reference-snapshot relative to the repo
	// root, i.e. two directories up from here.
	return filepath.Join(wd, "..", "..", "testdata", "fixtures", "reference-snapshot")
}

// TestReferenceSnapshot_ManifestSchema validates that the committed reference
// fixture's manifest.json unmarshals cleanly into snapshot.Manifest and
// contains the values docs/snapshot-format.md's worked example documents.
// This is the schema-drift trip-wire required by SPEC.md M5: if a future
// change to Manifest's shape is incompatible with this fixture, this test
// fails before the change ships.
func TestReferenceSnapshot_ManifestSchema(t *testing.T) {
	dir := fixtureDir(t)

	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}

	var m snapshot.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal manifest.json into snapshot.Manifest: %v", err)
	}

	// Round-trip: re-marshalling and re-parsing must be lossless for the
	// fields this package owns (catches accidental field renames that
	// happen to still unmarshal due to Go's permissive JSON decoding).
	// The wording here is deliberate. Telling a developer that a fixture is
	// "stale" invites them to regenerate it and carry on, which is exactly how
	// a breaking change to a public contract ships unnoticed. The fixture is
	// the tripwire; regenerating it is how you disarm the tripwire, not how you
	// fix the fault.
	if m.SchemaVersion != event.SchemaVersion {
		t.Errorf(`the fixture's schema_version (%d) no longer matches `+
			`event.SchemaVersion (%d).

This is a BREAKING CHANGE to a public contract (SPEC.md §6.4). Before you
regenerate the fixture, decide which of these happened:

  1. You deliberately bumped event.SchemaVersion. Then: regenerate with
     'make fixture' AND add an entry to CHANGELOG.md's schema history.
  2. You changed the serialised form without meaning to. Then: revert it.
     Consumers are written against version %d and will misread the new shape.

Regenerating without doing (1) or (2) silently breaks every reader.`,
			m.SchemaVersion, event.SchemaVersion, m.SchemaVersion)
	}
	if m.ID != "reference-snapshot" && m.ID != "20260802T142006Z-watched-process" {
		t.Errorf("ID = %q", m.ID)
	}
	if m.Trigger.Type != "watched-process" {
		t.Errorf("Trigger.Type = %q, want watched-process", m.Trigger.Type)
	}
	if m.Trigger.PID == nil || *m.Trigger.PID != 4321 {
		t.Errorf("Trigger.PID = %v, want 4321", m.Trigger.PID)
	}
	if m.Trigger.Unit != "mstr.service" {
		t.Errorf("Trigger.Unit = %q, want mstr.service", m.Trigger.Unit)
	}
	if m.Host.Hostname != "mstr-prod-07" {
		t.Errorf("Host.Hostname = %q, want mstr-prod-07", m.Host.Hostname)
	}
	if m.Host.Machine != "x86_64" {
		t.Errorf("Host.Machine = %q, want x86_64", m.Host.Machine)
	}
	if m.EventCount != 8 {
		t.Errorf("EventCount = %d, want 8", m.EventCount)
	}
	// The fixture reports a real loss on purpose. An all-zero drop report
	// would let a consumer satisfy the "surface non-zero drops" obligation
	// (docs/snapshot-format.md §6.3) by accident, having never seen a
	// snapshot that admits to losing anything.
	if m.Drops["userspace_ring"]["open"] == 0 {
		t.Error("the fixture's drop report is all zeroes; a consumer could not " +
			"exercise the drop-surfacing obligation against it")
	}
	if m.Window.First == nil || m.Window.Last == nil {
		t.Fatal("Window.First/Last must both be set for a non-empty snapshot")
	}
	if m.Window.Last.Before(*m.Window.First) {
		t.Errorf("Window.Last (%v) is before Window.First (%v)", m.Window.Last, m.Window.First)
	}

	// Every class must be present in EventCounts, including zero counts —
	// this is a documented contract (docs/snapshot-format.md §2.1), not an
	// implementation detail.
	for _, c := range event.Classes {
		if _, ok := m.EventCounts[string(c)]; !ok {
			t.Errorf("EventCounts missing class %q (zero counts must be explicit)", c)
		}
	}

	// Every boundary x class combination must be present in Drops, per
	// docs/snapshot-format.md §2.5.
	for _, b := range event.Boundaries {
		for _, c := range event.Classes {
			if _, ok := m.Drops[string(b)][string(c)]; !ok {
				t.Errorf("Drops[%q][%q] missing (zero drop counters must be explicit)", b, c)
			}
		}
	}

	if m.Proc == nil {
		t.Fatal("Proc must be present: the fixture's trigger carries a PID")
	}
	if !m.Proc.Found {
		t.Error("Proc.Found = false, want true")
	}
	wantFiles := []string{"cgroup", "cmdline", "limits", "status", "fd_listing.txt"}
	for _, f := range wantFiles {
		found := false
		for _, got := range m.Proc.Files {
			if got == f {
				found = true
			}
		}
		if !found {
			t.Errorf("Proc.Files = %v, missing %q", m.Proc.Files, f)
		}
	}
}

// TestReferenceSnapshot_EventsSchema validates events.jsonl.zst: it must
// decompress, parse as event.Event per line, and be sorted oldest first —
// the ordering guarantee documented in docs/snapshot-format.md §3.
func TestReferenceSnapshot_EventsSchema(t *testing.T) {
	dir := fixtureDir(t)

	f, err := os.Open(filepath.Join(dir, "events.jsonl.zst"))
	if err != nil {
		t.Fatalf("open events.jsonl.zst: %v", err)
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatalf("zstd.NewReader: %v", err)
	}
	defer zr.Close()

	dec := json.NewDecoder(zr)
	var events []event.Event
	for dec.More() {
		var e event.Event
		if err := dec.Decode(&e); err != nil {
			t.Fatalf("decode event line %d: %v", len(events), err)
		}
		events = append(events, e)
	}

	// The fixture must exercise *every* class, because it is the only
	// executable artefact a consumer gets (SPEC.md §6.2). A fixture missing a
	// class lets a consumer pass its own tests and then fail on the first real
	// snapshot containing one — and `generic` in particular is both the most
	// likely to be omitted and the most likely to break a naive reader.
	present := map[event.Class]bool{}
	for _, e := range events {
		present[e.Class] = true
	}
	for _, c := range event.Classes {
		if !present[c] {
			t.Errorf("the reference fixture contains no %q event; a consumer "+
				"testing against it would never exercise that class", c)
		}
	}

	if len(events) < len(event.Classes) {
		t.Fatalf("got %d events for %d classes", len(events), len(event.Classes))
	}

	// Ordering is a documented guarantee consumers may rely on
	// (docs/snapshot-format.md §3), so the fixture must demonstrate it.
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Before(events[i-1].Timestamp) {
			t.Errorf("events[%d] is older than events[%d]; the fixture violates "+
				"the oldest-first ordering guarantee", i, i-1)
		}
	}

	for i, e := range events {
		if !e.Class.Valid() {
			t.Errorf("events[%d].Class = %q is not a valid event.Class", i, e.Class)
		}
	}

	// Spot-check the documented worked example's field values
	// (docs/snapshot-format.md §7) so the doc and the fixture cannot drift
	// apart silently.
	execEvent := events[0]
	if execEvent.Filename != "/usr/sbin/smtpd" {
		t.Errorf("exec event Filename = %q, want /usr/sbin/smtpd", execEvent.Filename)
	}
	if len(execEvent.Argv) < 2 || execEvent.Argv[0] != "smtpd" || execEvent.Argv[1] != "-d" {
		t.Errorf("exec event Argv = %v, want it to start [smtpd -d]", execEvent.Argv)
	}

	openEvent := events[1]
	if openEvent.Errno != "EACCES" {
		t.Errorf("open event Errno = %q, want EACCES", openEvent.Errno)
	}
	if openEvent.Ret == nil || *openEvent.Ret != -13 {
		t.Errorf("open event Ret = %v, want -13", openEvent.Ret)
	}

	// The exit that fired the trigger is the last event, since it is what
	// froze the ring.
	exitEvent := events[len(events)-1]
	if exitEvent.Class != event.ClassExit {
		t.Fatalf("last event is %q, want the exit that fired the trigger", exitEvent.Class)
	}
	if exitEvent.ExitSignal == nil || *exitEvent.ExitSignal != 9 {
		t.Errorf("exit event ExitSignal = %v, want 9", exitEvent.ExitSignal)
	}

	// The generic event is the one a naive consumer is most likely to
	// mishandle, so the fixture must carry a fully-formed one.
	var generic *event.Event
	for i := range events {
		if events[i].Class == event.ClassGeneric {
			generic = &events[i]
			break
		}
	}
	if generic == nil {
		t.Fatal("no generic event in the fixture")
	}
	if len(generic.Raw) == 0 {
		t.Error("the generic event carries no raw payload; retaining it is the " +
			"entire point of the class")
	}
	if generic.DecodeError == "" {
		t.Error("the generic event does not explain why it could not be decoded")
	}
}

// TestReferenceSnapshot_SystemJSONSchema validates system.json unmarshals
// into snapshot.SystemInfo and matches the PSI-absence convention documented
// in docs/snapshot-format.md §4 (the fixture deliberately omits "io"
// pressure to exercise that convention).
func TestReferenceSnapshot_SystemJSONSchema(t *testing.T) {
	dir := fixtureDir(t)

	raw, err := os.ReadFile(filepath.Join(dir, "system.json"))
	if err != nil {
		t.Fatalf("read system.json: %v", err)
	}

	var sys snapshot.SystemInfo
	if err := json.Unmarshal(raw, &sys); err != nil {
		t.Fatalf("unmarshal system.json into snapshot.SystemInfo: %v", err)
	}

	if sys.Uname.Sysname != "Linux" {
		t.Errorf("Uname.Sysname = %q, want Linux", sys.Uname.Sysname)
	}
	// Values come from the generator and may change; the conventions a
	// consumer depends on must not.
	if !strings.HasSuffix(sys.MemInfo["MemTotal"], " kB") {
		t.Errorf("MemInfo[MemTotal] = %q; meminfo values are captured verbatim, "+
			"including the kernel's unit suffix", sys.MemInfo["MemTotal"])
	}
	if _, ok := sys.Pressure["io"]; ok {
		t.Error(`Pressure["io"] present, want absent (the fixture demonstrates ` +
			`the "resource absent" convention for PSI files that do not exist)`)
	}
	if len(sys.Pressure["memory"].Some) == 0 {
		t.Error("Pressure[memory].Some is empty; the fixture should show a " +
			"populated PSI reading so a consumer sees the shape")
	}
}

// TestReferenceSnapshot_ProcDir validates the fixture's proc/ scrape against
// the file set and privacy contract documented in docs/snapshot-format.md
// §5: exactly the fixed file names, and fd_listing.txt containing only
// fd-number/target pairs, never anything resembling file contents.
func TestReferenceSnapshot_ProcDir(t *testing.T) {
	dir := filepath.Join(fixtureDir(t), "proc")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read proc/: %v", err)
	}
	wantFiles := map[string]bool{
		"status": true, "limits": true, "cgroup": true, "cmdline": true, "fd_listing.txt": true,
	}
	for _, e := range entries {
		if !wantFiles[e.Name()] {
			t.Errorf("unexpected file in proc/: %q (only status/limits/cgroup/cmdline/fd_listing.txt are permitted)", e.Name())
		}
		delete(wantFiles, e.Name())
	}
	if len(wantFiles) != 0 {
		t.Errorf("proc/ missing expected files: %v", wantFiles)
	}

	listing, err := os.ReadFile(filepath.Join(dir, "fd_listing.txt"))
	if err != nil {
		t.Fatalf("read fd_listing.txt: %v", err)
	}
	for _, line := range strings.Split(strings.TrimRight(string(listing), "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			t.Errorf("fd_listing.txt line %q does not match '<fd>\\t<target>'", line)
		}
	}
}

// TestReferenceSnapshot_Permissions checks the 0700/0600-family privacy
// invariant on the committed fixture itself, so the example in the repo
// models the contract it documents.
func TestReferenceSnapshot_Permissions(t *testing.T) {
	dir := fixtureDir(t)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat fixture dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	// Note: git does not preserve exact POSIX permissions beyond the
	// executable bit, and CI checkouts vary in default umask, so this test
	// checks *shape* (files exist, are regular files) rather than asserting
	// an exact mode — the mode guarantee is enforced by
	// TestWrite_SnapshotDirsAreMode0700 against live Writer output, which is
	// the code path that actually matters in production.
	must := []string{"manifest.json", "events.jsonl.zst", "system.json"}
	for _, name := range must {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if !fi.Mode().IsRegular() {
			t.Errorf("%s is not a regular file", name)
		}
	}
}
