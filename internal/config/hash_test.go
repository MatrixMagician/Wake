package config

import "testing"

func TestHashDeterministic(t *testing.T) {
	a := Default().Hash()
	b := Default().Hash()
	if a != b {
		t.Fatalf("Hash() not deterministic: %s != %s", a, b)
	}
	if len(a) != 64 { // hex-encoded sha256
		t.Fatalf("expected 64 hex chars, got %d (%s)", len(a), a)
	}
}

func TestHashChangesWithContent(t *testing.T) {
	a := Default()
	b := Default()
	b.Snapshot.Dir = "/somewhere/else"
	if a.Hash() == b.Hash() {
		t.Fatal("Hash() must differ when config content differs")
	}
}

func TestHashStableAcrossFieldOrderInMap(t *testing.T) {
	a := Default()
	a.Classes = Classes{"exec": true, "exit": true, "signal": true, "oom": true, "open": true, "connect": true}
	b := Default()
	b.Classes = Classes{"connect": true, "open": true, "oom": true, "signal": true, "exit": true, "exec": true}
	if a.Hash() != b.Hash() {
		t.Fatal("Hash() must not depend on Go map iteration order")
	}
}
