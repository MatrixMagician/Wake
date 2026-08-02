package snapshot

import (
	"errors"
	"testing"
	"time"
)

func TestWrite_RenameFailure_LeavesNoPublishedSnapshot(t *testing.T) {
	fsys := newFakeFS()
	fsys.failRename = errors.New("simulated rename failure")

	w := NewWriter("/snapshots", "v0.0.0-test",
		WithFS(fsys),
		WithSystemInfoSource(fakeSystemInfoSource{info: SystemInfo{Uname: testUname()}}),
		WithProcSource(fakeProcSource{}),
		WithClock(func() time.Time { return time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC) }),
	)

	_, err := w.Write(Input{Trigger: TriggerInfo{Type: "manual", FiredAt: time.Now()}})
	if err == nil {
		t.Fatal("expected an error when Rename fails")
	}

	entries, err := fsys.ReadDir("/snapshots")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if isSnapshotID(e.Name) {
			t.Errorf("a published snapshot %q exists despite Rename failing", e.Name)
		}
	}
}

func TestWrite_WriteFileFailure_AbortsCleanly(t *testing.T) {
	fsys := newFakeFS()
	fsys.failWriteFile = errors.New("simulated disk full")
	fsys.failWriteFilePathSubstr = "manifest.json"

	w := NewWriter("/snapshots", "v0.0.0-test",
		WithFS(fsys),
		WithSystemInfoSource(fakeSystemInfoSource{info: SystemInfo{Uname: testUname()}}),
		WithProcSource(fakeProcSource{}),
		WithClock(func() time.Time { return time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC) }),
	)

	_, err := w.Write(Input{Trigger: TriggerInfo{Type: "manual", FiredAt: time.Now()}})
	if err == nil {
		t.Fatal("expected an error when writing manifest.json fails")
	}
}
