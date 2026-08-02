package config

import "testing"

func TestParseExitCodePredicate(t *testing.T) {
	cases := []struct {
		spec      string
		code      int32
		bySignal  bool
		wantMatch bool
	}{
		{"", 0, false, true},
		{"any", 137, true, true},
		{"signal", 0, true, true},
		{"signal", 0, false, false},
		{"nonzero", 0, false, false},
		{"nonzero", 1, false, true},
		{"nonzero", 0, true, true},
		{"137", 137, false, true},
		{"137", 138, false, false},
		{"137", 137, true, false}, // signal death never matches a code comparison
		{">0", 1, false, true},
		{">0", 0, false, false},
		{">=1", 1, false, true},
		{"<0", -1, false, true},
		{"<=-1", -1, false, true},
		{"<=-1", 0, false, false},
	}
	for _, c := range cases {
		p, err := ParseExitCodePredicate(c.spec)
		if err != nil {
			t.Fatalf("ParseExitCodePredicate(%q): %v", c.spec, err)
		}
		got := p.Match(c.code, c.bySignal)
		if got != c.wantMatch {
			t.Errorf("%q.Match(%d, signal=%v) = %v, want %v", c.spec, c.code, c.bySignal, got, c.wantMatch)
		}
	}
}

func TestParseExitCodePredicateInvalid(t *testing.T) {
	for _, spec := range []string{"abc", ">abc", "1.5", "=="} {
		if _, err := ParseExitCodePredicate(spec); err == nil {
			t.Errorf("expected error for %q", spec)
		}
	}
}

func TestParseSignalName(t *testing.T) {
	if _, err := ParseSignalName("SIGSEGV"); err != nil {
		t.Fatalf("SIGSEGV should be recognised: %v", err)
	}
	if _, err := ParseSignalName("sigsegv"); err != nil {
		t.Fatalf("signal names should be case-insensitive: %v", err)
	}
	if _, err := ParseSignalName("SIGNOTREAL"); err == nil {
		t.Fatal("expected error for unknown signal name")
	}
}
