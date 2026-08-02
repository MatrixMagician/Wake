package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOSProcSource_Scrape_Found(t *testing.T) {
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "4321")
	writeFixtureFile(t, filepath.Join(pidDir, "status"), "Name:\tsmtpd\n")
	writeFixtureFile(t, filepath.Join(pidDir, "limits"), "Max open files            1024\n")
	writeFixtureFile(t, filepath.Join(pidDir, "cgroup"), "0::/system.slice/mstr.service\n")
	writeFixtureFile(t, filepath.Join(pidDir, "cmdline"), "smtpd\x00-d\x00")

	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(pidDir, "fd", "0")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(pidDir, "fd", "3")); err != nil {
		t.Fatal(err)
	}

	src := &OSProcSource{ProcRoot: procRoot}
	files, fds, found, err := src.Scrape(4321)
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if string(files["status"]) != "Name:\tsmtpd\n" {
		t.Errorf("files[status] = %q", files["status"])
	}
	if string(files["cmdline"]) != "smtpd\x00-d\x00" {
		t.Errorf("files[cmdline] = %q", files["cmdline"])
	}
	if fds["0"] != "/dev/null" {
		t.Errorf("fds[0] = %q, want /dev/null", fds["0"])
	}
	if fds["3"] != "socket:[12345]" {
		t.Errorf("fds[3] = %q, want socket:[12345]", fds["3"])
	}

	// Hard privacy line: the scrape must never contain anything resembling
	// file contents from an fd target (a listing of names/targets is fine,
	// the bytes behind those targets are not — nothing in this test fixture
	// puts file contents within reach, which is itself the point: the API
	// shape makes it impossible to accidentally wire that up).
	for name := range files {
		if name != "status" && name != "limits" && name != "cgroup" && name != "cmdline" {
			t.Errorf("unexpected file captured: %q (only status/limits/cgroup/cmdline are permitted)", name)
		}
	}
}

func TestOSProcSource_Scrape_NotFound(t *testing.T) {
	src := &OSProcSource{ProcRoot: t.TempDir()}
	files, fds, found, err := src.Scrape(99999)
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if found {
		t.Error("found = true, want false for a nonexistent pid")
	}
	if files != nil || fds != nil {
		t.Errorf("files=%v fds=%v, want nil for a nonexistent pid", files, fds)
	}
}

func TestOSProcSource_Scrape_PartialFiles(t *testing.T) {
	// Only "status" present: limits/cgroup/cmdline missing. Must still
	// report found=true with a partial file set, not fail outright.
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "42")
	writeFixtureFile(t, filepath.Join(pidDir, "status"), "Name:\tpartial\n")

	src := &OSProcSource{ProcRoot: procRoot}
	files, _, found, err := src.Scrape(42)
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if len(files) != 1 {
		t.Errorf("files = %v, want exactly {status: ...}", files)
	}
}

func TestWriteProcDir_SummaryReflectsFiles(t *testing.T) {
	fsys := newFakeFS()
	src := fakeProcSource{byPID: map[int32]fakeProcResult{
		7: {found: true, files: map[string][]byte{"status": []byte("x")}},
	}}
	summary, err := writeProcDir(fsys, "/snap/proc", 7, src)
	if err != nil {
		t.Fatalf("writeProcDir: %v", err)
	}
	if !summary.Found {
		t.Error("summary.Found = false, want true")
	}
	if len(summary.Files) != 1 || summary.Files[0] != "status" {
		t.Errorf("summary.Files = %v, want [status]", summary.Files)
	}
}
