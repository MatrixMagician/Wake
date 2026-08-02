package enrich

import (
	"os"
	"testing"
)

// TestProcfsSourceAgainstSelf sanity-checks ProcfsSource against the real
// /proc for the test process's own pid. This is the one test in the package
// that touches a real /proc — deliberately narrow (self only, read-only
// files every unprivileged process can read) so the "unit tests never need
// privileges" rule (CLAUDE.md) still holds. It is skipped when /proc is
// unavailable (e.g. non-Linux CI) rather than failing the build.
func TestProcfsSourceAgainstSelf(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("no /proc/self/status on this platform")
	}

	s := NewProcfsSource()
	pid := int32(os.Getpid())

	comm, ppid, uid, ok := s.Status(pid)
	if !ok {
		t.Fatal("Status(self) reported not ok")
	}
	if comm == "" {
		t.Error("Status(self): comm is empty")
	}
	if ppid <= 0 {
		t.Errorf("Status(self): ppid = %d, want > 0", ppid)
	}
	if uid != uint32(os.Getuid()) {
		t.Errorf("Status(self): uid = %d, want %d", uid, os.Getuid())
	}

	if _, ok := s.Cgroup(pid); !ok {
		t.Error("Cgroup(self) reported not ok on a cgroup v2 host")
	}

	// Root's own uid (0) should resolve on any normal Linux /etc/passwd.
	if name, ok := s.User(0); !ok || name != "root" {
		t.Errorf("User(0) = %q, %v, want root, true", name, ok)
	}

	// A wildly implausible pid must report ok=false, not panic or fabricate.
	if _, _, _, ok := s.Status(1 << 30); ok {
		t.Error("Status(huge pid) unexpectedly ok")
	}
}
