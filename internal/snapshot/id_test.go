package snapshot

import (
	"testing"
	"time"
)

func TestSnapshotID(t *testing.T) {
	ts := time.Date(2026, 8, 2, 14, 20, 7, 123456789, time.UTC)
	got := snapshotID(ts, "manual")
	want := "20260802T142007Z-manual"
	if got != want {
		t.Errorf("snapshotID = %q, want %q", got, want)
	}
}

func TestSnapshotID_ConvertsToUTC(t *testing.T) {
	loc := time.FixedZone("TEST+5", 5*3600)
	ts := time.Date(2026, 8, 2, 19, 20, 7, 0, loc) // 14:20:07 UTC
	got := snapshotID(ts, "manual")
	want := "20260802T142007Z-manual"
	if got != want {
		t.Errorf("snapshotID = %q, want %q (must normalise to UTC)", got, want)
	}
}

func TestSanitiseTriggerType(t *testing.T) {
	cases := []struct{ in, want string }{
		{"manual", "manual"},
		{"systemd-unit-failed", "systemd-unit-failed"},
		{"watched-process", "watched-process"},
		{"Some Weird Type", "some-weird-type"},
		{"has/slash", "has-slash"},
		{"", "unknown"},
		{"  ", "unknown"},
	}
	for _, c := range cases {
		got := sanitiseTriggerType(c.in)
		if got != c.want {
			t.Errorf("sanitiseTriggerType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsSnapshotID(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"20260802T142007Z-manual", true},
		{".20260802T142007Z-manual.tmp", false},
		{"noHyphenHere", false},
		{"", false},
	}
	for _, c := range cases {
		got := isSnapshotID(c.name)
		if got != c.want {
			t.Errorf("isSnapshotID(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
