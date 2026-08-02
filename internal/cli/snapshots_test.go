package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `wake snapshots prune` was once a stub: it printed what it would remove and
// then removed nothing, even with --yes, and ignored --max-size entirely. It
// looked completely convincing in a terminal, which is exactly why it survived
// a manual check. These tests assert on the filesystem afterwards rather than
// on the output.

// makeSnapshots creates n snapshot directories, oldest first, each `size` bytes.
func makeSnapshots(t *testing.T, n, size int) string {
	t.Helper()
	root := t.TempDir()

	for i := 1; i <= n; i++ {
		dir := filepath.Join(root, snapshotName(i))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("creating a test snapshot: %v", err)
		}
		manifest, err := json.Marshal(map[string]any{
			"schema_version": 1,
			"trigger":        map[string]string{"type": "manual"},
			"event_count":    i,
		})
		if err != nil {
			t.Fatalf("encoding a test manifest: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o600); err != nil {
			t.Fatalf("writing a test manifest: %v", err)
		}
		if err := os.WriteFile(
			filepath.Join(dir, "events.jsonl.zst"), make([]byte, size), 0o600,
		); err != nil {
			t.Fatalf("writing test events: %v", err)
		}
	}
	return root
}

// snapshotName produces IDs that sort chronologically, as real ones do.
func snapshotName(i int) string {
	return "2026080" + string(rune('0'+i)) + "T120000Z-manual"
}

func remaining(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading the snapshot root: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func runSnapshots(t *testing.T, args ...string) (string, bool) {
	t.Helper()
	cmd := snapshotsCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err != nil {
		out.WriteString(err.Error())
	}
	return out.String(), err != nil
}

// TestPruneWithoutConfirmationDeletesNothing is the guard on the safety
// property: this command deletes evidence, so the default must be inert.
func TestPruneWithoutConfirmationDeletesNothing(t *testing.T) {
	root := makeSnapshots(t, 5, 1024)

	out, failed := runSnapshots(t, "prune", "--dir", root, "--keep", "2")
	if failed {
		t.Fatalf("prune reported failure: %s", out)
	}
	if got := len(remaining(t, root)); got != 5 {
		t.Fatalf("a dry run deleted snapshots: %d remain, want 5", got)
	}
	if !strings.Contains(out, "would remove") {
		t.Errorf("a dry run should say what it would do, got: %s", out)
	}
	if !strings.Contains(out, "--yes") {
		t.Errorf("a dry run should say how to apply it, got: %s", out)
	}
}

// TestPruneWithConfirmationActuallyDeletes is the regression: --yes used to
// print "removed" and leave every directory in place.
func TestPruneWithConfirmationActuallyDeletes(t *testing.T) {
	root := makeSnapshots(t, 5, 1024)

	out, failed := runSnapshots(t, "prune", "--dir", root, "--keep", "2", "--yes")
	if failed {
		t.Fatalf("prune reported failure: %s", out)
	}

	left := remaining(t, root)
	if len(left) != 2 {
		t.Fatalf("%d snapshots remain, want 2: %v", len(left), left)
	}
	// Oldest first: the two newest must be the survivors.
	for _, want := range []string{snapshotName(4), snapshotName(5)} {
		if !contains(left, want) {
			t.Errorf("%s should have been kept; remaining: %v", want, left)
		}
	}
}

func TestPruneBySize(t *testing.T) {
	// Five snapshots of ~10 KiB. A 25 KiB budget fits two.
	root := makeSnapshots(t, 5, 10*1024)

	if out, failed := runSnapshots(
		t, "prune", "--dir", root, "--max-size", "25KiB", "--yes",
	); failed {
		t.Fatalf("prune reported failure: %s", out)
	}

	if got := len(remaining(t, root)); got > 2 {
		t.Errorf("%d snapshots remain under a 25 KiB budget; the size bound did "+
			"not bind", got)
	}
}

func TestPruneRefusesWithoutABound(t *testing.T) {
	root := makeSnapshots(t, 3, 1024)

	out, failed := runSnapshots(t, "prune", "--dir", root, "--yes")
	if !failed {
		t.Fatal("prune with no bound was accepted; it is ambiguous whether that " +
			"means 'keep everything' or 'keep nothing', and one of those deletes " +
			"every snapshot on the box")
	}
	if got := len(remaining(t, root)); got != 3 {
		t.Errorf("snapshots were deleted despite the error: %d remain", got)
	}
	if !strings.Contains(out, "--keep") {
		t.Errorf("the error should name the missing flags, got: %s", out)
	}
}

func TestPruneRejectsAnUnparseableSize(t *testing.T) {
	root := makeSnapshots(t, 3, 1024)

	if _, failed := runSnapshots(
		t, "prune", "--dir", root, "--max-size", "banana", "--yes",
	); !failed {
		t.Fatal("an unparseable --max-size was accepted")
	}
	if got := len(remaining(t, root)); got != 3 {
		t.Errorf("snapshots were deleted despite a bad size: %d remain", got)
	}
}

func TestPruneIsIdempotent(t *testing.T) {
	root := makeSnapshots(t, 4, 1024)

	for range 3 {
		if out, failed := runSnapshots(
			t, "prune", "--dir", root, "--keep", "2", "--yes",
		); failed {
			t.Fatalf("prune reported failure: %s", out)
		}
	}
	if got := len(remaining(t, root)); got != 2 {
		t.Errorf("repeated pruning did not settle: %d remain, want 2", got)
	}
}

func TestParseSize(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"1024", 1024, false},
		{"1KiB", 1024, false},
		{"1kb", 1024, false},
		{"2MiB", 2 * 1024 * 1024, false},
		{"1GiB", 1024 * 1024 * 1024, false},
		{"1.5GiB", 1610612736, false},
		{" 2 GB ", 2 * 1024 * 1024 * 1024, false},
		{"500B", 500, false},
		{"", 0, true},
		{"banana", 0, true},
		{"-5MiB", 0, true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSize(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseSize(%q) = %d, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSize(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseSize(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestListReportsAnEmptyDirectoryHonestly(t *testing.T) {
	out, failed := runSnapshots(t, "list", "--dir", t.TempDir())
	if failed {
		t.Fatalf("listing an empty directory failed: %s", out)
	}
	// "No snapshots" is the normal state for a healthy box, and saying so
	// beats printing nothing and leaving the operator wondering.
	if !strings.Contains(out, "No snapshots") {
		t.Errorf("an empty listing should say so, got: %q", out)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
