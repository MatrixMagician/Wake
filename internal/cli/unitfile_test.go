package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The shipped systemd unit is code that runs in production, but it is not
// compiled and nothing type-checks it, so it rots in a way that only shows up
// on a real host during a real incident. Two failures were found by actually
// installing and exercising it, and both looked like success at the time:
//
//   - ExecReload=/bin/kill -HUP terminated the daemon, because Wake did not
//     handle SIGHUP and the default disposition of an unhandled SIGHUP is to
//     terminate. systemd logged "Reloaded ... successfully" and the recorder
//     was gone.
//   - The capability set omitted CAP_SYS_PTRACE, so every readlink of
//     /proc/<pid>/fd/* was denied and the fd listing in every snapshot was
//     written blank. Nothing failed; the evidence was simply absent.
//
// These tests pin both, so re-hardening the unit cannot silently reintroduce
// either one.

func unitFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", "wake.service")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestUnitDoesNotAdvertiseReload guards the more dangerous of the two: a
// reload that stops the recorder is worse than no reload, because the
// operator believes it worked.
func TestUnitDoesNotAdvertiseReload(t *testing.T) {
	for _, line := range strings.Split(unitFile(t), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "ExecReload=") {
			t.Errorf("unit declares %q, but Wake does not reload in place: an "+
				"ExecReload that sends a signal Wake does not act on will stop "+
				"the recorder while systemd reports success", trimmed)
		}
	}
}

// TestUnitGrantsCapabilitiesTheCodeNeeds pins the capability set against what
// the daemon actually does, rather than against what the comments claim.
func TestUnitGrantsCapabilitiesTheCodeNeeds(t *testing.T) {
	unit := unitFile(t)

	required := map[string]string{
		"CAP_BPF":             "loading BPF programs",
		"CAP_PERFMON":         "attaching to tracepoints",
		"CAP_SYS_RESOURCE":    "raising RLIMIT_MEMLOCK on older kernels",
		"CAP_DAC_READ_SEARCH": "reading /proc of processes owned by other users",
		"CAP_SYS_PTRACE":      "readlink of /proc/<pid>/fd/*, which is gated on PTRACE_MODE_READ",
	}

	for _, directive := range []string{"AmbientCapabilities", "CapabilityBoundingSet"} {
		re := regexp.MustCompile(`(?m)^` + directive + `=(.*)$`)
		m := re.FindStringSubmatch(unit)
		if m == nil {
			t.Fatalf("unit has no %s= directive", directive)
		}
		granted := strings.Fields(m[1])
		for capName, why := range required {
			if !slicesContains(granted, capName) {
				t.Errorf("%s= omits %s, needed for %s", directive, capName, why)
			}
		}
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
