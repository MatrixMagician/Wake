package doctor

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReportOK(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   []Result
		want bool
	}{
		{"empty", nil, true},
		{"all passing", []Result{{OK: true, Fatal: true}, {OK: true}}, true},
		{"non-fatal failure", []Result{{OK: true, Fatal: true}, {OK: false}}, true},
		{"fatal failure", []Result{{OK: true}, {OK: false, Fatal: true}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Report{Results: tc.in}).OK(); got != tc.want {
				t.Errorf("OK() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMemlockResult covers the case this check could not previously report:
// a limit too small to load the ring buffer, held by a process with no way to
// raise it.
func TestMemlockResult(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		cur    uint64
		isRoot bool
		wantOK bool
	}{
		{"unlimited", unix.RLIM_INFINITY, false, true},
		{"root can always raise it", 4096, true, true},
		{"ample limit without root", minMemlockBytes, false, true},
		{"too small and not root", 65536, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := memlockResult(tc.cur, tc.isRoot)
			if got.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v (detail: %s)", got.OK, tc.wantOK, got.Detail)
			}
			if got.Name == "" || got.Detail == "" {
				t.Error("every result must name itself and say what was observed")
			}
			if !got.OK {
				// The design rule for this package: a failure names its remedy.
				if got.Remedy == "" {
					t.Error("a failing check must carry a remedy")
				}
				if got.Fatal {
					t.Error("a low memlock is recoverable, so it must not be fatal")
				}
			}
		})
	}
}

// TestEveryResultIsAnswerable guards the property this package lost when three
// checks could only ever return OK: a reader must be able to trust the status
// column. Run's checks are host-dependent, so this asserts the weaker
// invariant that each one identifies itself and reports something.
func TestRunResultsAreWellFormed(t *testing.T) {
	t.Parallel()
	report := Run()
	if len(report.Results) == 0 {
		t.Fatal("Run returned no checks")
	}
	seen := map[string]bool{}
	for _, c := range report.Results {
		if c.Name == "" {
			t.Error("a check reported no name")
		}
		if seen[c.Name] {
			t.Errorf("duplicate check name %q", c.Name)
		}
		seen[c.Name] = true
		if c.Detail == "" {
			t.Errorf("check %q reported no detail", c.Name)
		}
		if !c.OK && c.Remedy == "" {
			t.Errorf("failing check %q carries no remedy; a diagnosis without one "+
				"is not help", c.Name)
		}
	}
	for _, n := range report.Notes {
		if strings.TrimSpace(n) == "" {
			t.Error("an empty note was emitted")
		}
	}
}
