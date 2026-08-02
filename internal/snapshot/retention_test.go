package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

// makeSnapshotDir creates a fake finished-snapshot directory containing a
// single file of size sizeBytes, so DirSize has something deterministic to
// measure.
func makeSnapshotDir(t *testing.T, root, id string, sizeBytes int) {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl.zst"), make([]byte, sizeBytes), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPrune_ByCount(t *testing.T) {
	root := t.TempDir()
	makeSnapshotDir(t, root, "20260801T100000Z-manual", 100)
	makeSnapshotDir(t, root, "20260801T110000Z-manual", 100)
	makeSnapshotDir(t, root, "20260801T120000Z-manual", 100)

	p := NewPruner(root)
	result, err := p.Prune(RetentionSettings{MaxCount: 2}, false)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(result.Removed) != 1 || result.Removed[0] != "20260801T100000Z-manual" {
		t.Errorf("Removed = %v, want [20260801T100000Z-manual] (oldest first)", result.Removed)
	}
	if len(result.Kept) != 2 {
		t.Errorf("Kept = %v, want 2 entries", result.Kept)
	}
	if _, err := os.Stat(filepath.Join(root, "20260801T100000Z-manual")); !os.IsNotExist(err) {
		t.Errorf("oldest snapshot dir should have been removed from disk")
	}
	if _, err := os.Stat(filepath.Join(root, "20260801T120000Z-manual")); err != nil {
		t.Errorf("newest snapshot dir should still exist: %v", err)
	}
}

func TestPrune_BySize(t *testing.T) {
	root := t.TempDir()
	makeSnapshotDir(t, root, "20260801T100000Z-manual", 1000)
	makeSnapshotDir(t, root, "20260801T110000Z-manual", 1000)
	makeSnapshotDir(t, root, "20260801T120000Z-manual", 1000)

	p := NewPruner(root)
	result, err := p.Prune(RetentionSettings{MaxTotalBytes: 2000}, false)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(result.Removed) != 1 {
		t.Fatalf("Removed = %v, want 1 entry", result.Removed)
	}
	if result.Removed[0] != "20260801T100000Z-manual" {
		t.Errorf("Removed[0] = %q, want oldest", result.Removed[0])
	}
	if result.FreedBytes != 1000 {
		t.Errorf("FreedBytes = %d, want 1000", result.FreedBytes)
	}
}

func TestPrune_DryRunDoesNotTouchDisk(t *testing.T) {
	root := t.TempDir()
	makeSnapshotDir(t, root, "20260801T100000Z-manual", 100)
	makeSnapshotDir(t, root, "20260801T110000Z-manual", 100)

	p := NewPruner(root)
	result, err := p.Prune(RetentionSettings{MaxCount: 1}, true)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(result.Removed) != 1 {
		t.Fatalf("Removed = %v, want 1 entry (computed even in dry-run)", result.Removed)
	}
	if _, err := os.Stat(filepath.Join(root, result.Removed[0])); err != nil {
		t.Errorf("dry-run must not remove anything from disk, but: %v", err)
	}
}

func TestPrune_NeverDeletesStagingDirs(t *testing.T) {
	root := t.TempDir()
	// A staging dir has a leading dot; it must never be a prune candidate
	// even when it's the "oldest" lexically once the dot is stripped.
	if err := os.MkdirAll(filepath.Join(root, ".20260101T000000Z-manual.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	makeSnapshotDir(t, root, "20260801T100000Z-manual", 100)

	p := NewPruner(root)
	result, err := p.Prune(RetentionSettings{MaxCount: 0}, false)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(result.Removed) != 0 {
		t.Errorf("Removed = %v, want none (unlimited retention)", result.Removed)
	}
	if _, err := os.Stat(filepath.Join(root, ".20260101T000000Z-manual.tmp")); err != nil {
		t.Errorf("staging dir must never be removed by Prune: %v", err)
	}
}

func TestPrune_ZeroSettingsIsUnlimited(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		makeSnapshotDir(t, root, "20260801T1"+string(rune('0'+i))+"0000Z-manual", 1000)
	}
	p := NewPruner(root)
	result, err := p.Prune(RetentionSettings{}, false)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(result.Removed) != 0 {
		t.Errorf("Removed = %v, want none with zero settings", result.Removed)
	}
	if len(result.Kept) != 5 {
		t.Errorf("Kept = %v, want 5", result.Kept)
	}
}

func TestPrune_BothBoundsCombine(t *testing.T) {
	root := t.TempDir()
	makeSnapshotDir(t, root, "20260801T100000Z-manual", 1000)
	makeSnapshotDir(t, root, "20260801T110000Z-manual", 1000)
	makeSnapshotDir(t, root, "20260801T120000Z-manual", 1000)
	makeSnapshotDir(t, root, "20260801T130000Z-manual", 1000)

	p := NewPruner(root)
	// MaxCount alone would keep 3; MaxTotalBytes alone would keep 2. The
	// tighter (more aggressive) bound must win.
	result, err := p.Prune(RetentionSettings{MaxCount: 3, MaxTotalBytes: 2000}, false)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(result.Kept) != 2 {
		t.Errorf("Kept = %v, want 2 (tighter bound applies)", result.Kept)
	}
}
