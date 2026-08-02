package snapshot

import (
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// The snapshot format documents a guarantee that consumers are told they may
// rely on: "a reader that lists the snapshots root and finds a directory not
// starting with `.` can assume it is fully written". That is an atomicity
// contract between two processes, and it rests on two behaviours that are
// invisible from a finished snapshot — the staging directory being hidden, and
// publication being a single rename.
//
// Nothing exercised either, so a mutation that made staging visible passed
// every test. A consumer following the documented rule would then have read a
// half-written snapshot and drawn conclusions from a truncated event stream.

// observingFS records the paths a write touches, so the sequence of filesystem
// operations can be asserted rather than only the end state.
type observingFS struct {
	FS
	created []string
	renames [][2]string
}

func (o *observingFS) MkdirAll(path string, perm fs.FileMode) error {
	o.created = append(o.created, path)
	return o.FS.MkdirAll(path, perm)
}

func (o *observingFS) CreateFile(path string, perm fs.FileMode) (io.WriteCloser, error) {
	o.created = append(o.created, path)
	return o.FS.CreateFile(path, perm)
}

func (o *observingFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	o.created = append(o.created, path)
	return o.FS.WriteFile(path, data, perm)
}

func (o *observingFS) Rename(oldpath, newpath string) error {
	o.renames = append(o.renames, [2]string{oldpath, newpath})
	return o.FS.Rename(oldpath, newpath)
}

func testInput() Input {
	now := time.Date(2026, 8, 2, 14, 20, 0, 0, time.UTC)
	return Input{
		Events: []event.Event{
			{Timestamp: now, Class: event.ClassExec, PID: 1},
			{Timestamp: now.Add(time.Second), Class: event.ClassExit, PID: 1},
		},
		Drops:      (&event.Drops{}).Report(),
		Trigger:    TriggerInfo{Type: "manual", Reason: "test", FiredAt: now},
		ConfigHash: "hash",
	}
}

// TestStagingDirectoryIsHidden is the guarantee stated in
// docs/snapshot-format.md §1. A visible staging directory would look exactly
// like a complete snapshot to a conforming reader.
func TestStagingDirectoryIsHidden(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	obs := &observingFS{FS: OSFS{}}
	w := NewWriter(root, "test", WithFS(obs))

	res, err := w.Write(testInput())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	var staging string
	for _, path := range obs.created {
		rel := strings.TrimPrefix(strings.TrimPrefix(path, root), "/")
		first, _, _ := strings.Cut(rel, "/")
		if first == "" {
			continue
		}
		if first != res.ID {
			staging = first
			break
		}
	}
	if staging == "" {
		t.Fatal("nothing was written outside the published directory, so the " +
			"snapshot was assembled in place; a reader could observe it half-written")
	}
	if !strings.HasPrefix(staging, ".") {
		t.Errorf("the staging directory is %q; docs/snapshot-format.md tells readers "+
			"that any directory without a leading dot is fully written, so this "+
			"would be read as a complete snapshot mid-write", staging)
	}
}

// TestPublicationIsASingleRename pins the other half of the atomicity claim.
func TestPublicationIsASingleRename(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	obs := &observingFS{FS: OSFS{}}
	w := NewWriter(root, "test", WithFS(obs))

	res, err := w.Write(testInput())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(obs.renames) != 1 {
		t.Fatalf("%d renames; publication must be exactly one so it is atomic",
			len(obs.renames))
	}
	from, to := obs.renames[0][0], obs.renames[0][1]
	if to != res.Path {
		t.Errorf("renamed to %q, want the published path %q", to, res.Path)
	}
	if !strings.Contains(from, "/.") {
		t.Errorf("renamed from %q, which is not a hidden staging path", from)
	}
}

// failingFS fails the nth write, so a mid-write failure can be simulated.
type failingFS struct {
	FS
	failOn string
}

func (f *failingFS) CreateFile(path string, perm fs.FileMode) (io.WriteCloser, error) {
	if strings.Contains(path, f.failOn) {
		return nil, errors.New("simulated failure")
	}
	return f.FS.CreateFile(path, perm)
}

func (f *failingFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	if strings.Contains(path, f.failOn) {
		return errors.New("simulated failure")
	}
	return f.FS.WriteFile(path, data, perm)
}

// TestFailedWriteLeavesNoVisibleSnapshot is the property that matters when a
// disk fills mid-snapshot, which is precisely the sort of incident Wake is
// deployed for: the failure must not leave something a reader would consume.
func TestFailedWriteLeavesNoVisibleSnapshot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	w := NewWriter(root, "test", WithFS(&failingFS{FS: OSFS{}, failOn: "manifest.json"}))

	if _, err := w.Write(testInput()); err == nil {
		t.Fatal("a failed manifest write was reported as success")
	}

	entries, err := OSFS{}.ReadDir(root)
	if err != nil {
		t.Fatalf("reading the snapshot root: %v", err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name, ".") {
			t.Errorf("a failed write left the visible directory %q, which a "+
				"conforming reader would treat as a complete snapshot", e.Name)
		}
	}
}
