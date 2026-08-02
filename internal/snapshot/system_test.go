package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOSSystemInfoSource_Capture(t *testing.T) {
	procRoot := t.TempDir()
	writeFixtureFile(t, filepath.Join(procRoot, "meminfo"),
		"MemTotal:       16384000 kB\nMemFree:         2048000 kB\n")
	writeFixtureFile(t, filepath.Join(procRoot, "pressure", "memory"),
		"some avg10=0.50 avg60=0.20 avg300=0.10 total=12345\n"+
			"full avg10=0.10 avg60=0.05 avg300=0.01 total=6789\n")
	writeFixtureFile(t, filepath.Join(procRoot, "pressure", "cpu"),
		"some avg10=1.20 avg60=0.80 avg300=0.30 total=99999\n")
	// No "io" file: PSI disabled for io, or kernel too old. Must not error.
	writeFixtureFile(t, filepath.Join(procRoot, "uptime"), "123456.78 987654.32\n")
	writeFixtureFile(t, filepath.Join(procRoot, "loadavg"), "0.10 0.20 0.30 1/234 5678\n")

	src := &OSSystemInfoSource{
		ProcRoot: procRoot,
		UnameFunc: func() (Uname, error) {
			return Uname{Sysname: "Linux", Nodename: "fixture-host", Release: "6.10.0", Version: "#1", Machine: "x86_64"}, nil
		},
	}

	info, err := src.Capture()
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if info.Uname.Nodename != "fixture-host" {
		t.Errorf("Uname.Nodename = %q, want fixture-host", info.Uname.Nodename)
	}
	if info.MemInfo["MemTotal"] != "16384000 kB" {
		t.Errorf("MemInfo[MemTotal] = %q, want %q", info.MemInfo["MemTotal"], "16384000 kB")
	}
	if info.Pressure["memory"].Some["avg10"] != "0.50" {
		t.Errorf("Pressure[memory].Some[avg10] = %q, want 0.50", info.Pressure["memory"].Some["avg10"])
	}
	if info.Pressure["memory"].Full["total"] != "6789" {
		t.Errorf("Pressure[memory].Full[total] = %q, want 6789", info.Pressure["memory"].Full["total"])
	}
	if _, ok := info.Pressure["io"]; ok {
		t.Errorf("Pressure[io] present, want absent (file did not exist)")
	}
	if info.Pressure["cpu"].Full != nil {
		t.Errorf("Pressure[cpu].Full = %+v, want nil (cpu has no full line)", info.Pressure["cpu"].Full)
	}
	if info.Uptime != 123456.78 {
		t.Errorf("Uptime = %v, want 123456.78", info.Uptime)
	}
	if info.LoadAvg != [3]float64{0.10, 0.20, 0.30} {
		t.Errorf("LoadAvg = %v, want [0.10 0.20 0.30]", info.LoadAvg)
	}
}

func TestOSSystemInfoSource_Capture_MissingProcFiles(t *testing.T) {
	// An entirely empty /proc fixture: every optional file absent. Capture
	// must still succeed (best-effort capture — system.json is diagnostic
	// context, not load-bearing).
	src := &OSSystemInfoSource{
		ProcRoot: t.TempDir(),
		UnameFunc: func() (Uname, error) {
			return Uname{Sysname: "Linux"}, nil
		},
	}
	info, err := src.Capture()
	if err != nil {
		t.Fatalf("Capture with missing /proc files: %v", err)
	}
	if info.MemInfo != nil {
		t.Errorf("MemInfo = %+v, want nil", info.MemInfo)
	}
	if info.Pressure != nil {
		t.Errorf("Pressure = %+v, want nil", info.Pressure)
	}
}

func TestOSSystemInfoSource_Capture_UnameError(t *testing.T) {
	wantErr := os.ErrPermission
	src := &OSSystemInfoSource{
		ProcRoot:  t.TempDir(),
		UnameFunc: func() (Uname, error) { return Uname{}, wantErr },
	}
	_, err := src.Capture()
	if err == nil {
		t.Fatal("expected an error when UnameFunc fails")
	}
}
