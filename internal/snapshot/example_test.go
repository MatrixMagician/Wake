package snapshot_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The example consumer in examples/conformance is evidence for a claim SPEC.md
// §6.2 makes: that the snapshot format is implementable from the documentation
// alone. Evidence that has rotted proves nothing, so it is exercised here.
//
// This is the only test in Wake that shells out to another language. That is
// the point: a reference reader written in Go would share Wake's own
// assumptions about the format and could pass while the contract was in fact
// unimplementable by anyone else.

func TestExampleConsumerReadsTheReferenceFixture(t *testing.T) {
	t.Parallel()

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available; the example consumer cannot be exercised")
	}
	requireZstdDecoder(t, python)

	script := filepath.Join("..", "..", "examples", "conformance", "conformance.py")
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "reference-snapshot")

	out, err := exec.Command(python, script, fixture).CombinedOutput()
	if err != nil {
		t.Fatalf("the example consumer could not read the reference fixture: %v\n%s",
			err, out)
	}

	got := string(out)
	if !strings.Contains(got, "CONFORMANT") {
		t.Errorf("the example consumer did not report conformance:\n%s", got)
	}

	// Each obligation should be visibly exercised, so that a fixture change
	// which quietly stops covering one is caught. The drop warning in
	// particular: the fixture reports a real loss on purpose, and a consumer
	// staying quiet about it is the failure §6.3 exists to prevent.
	for _, want := range []struct{ marker, why string }{
		{"[§6.1]", "schema_version was not checked"},
		{"[§6.3] INCOMPLETE", "the fixture's non-zero drop count was not surfaced"},
		{"[§6.4] retained", "the fixture's generic event was not retained"},
		{"ordering: oldest-first", "the ordering guarantee was not verified"},
	} {
		if !strings.Contains(got, want.marker) {
			t.Errorf("%s — expected %q in the output:\n%s", want.why, want.marker, got)
		}
	}
}

// requireZstdDecoder skips rather than fails when the host has no way to
// decompress the events stream. The example consumer follows the format
// document's advice to use "any standard zstd decoder", which in Python means
// the zstandard module if installed and the zstdcat binary otherwise; a host
// with neither cannot exercise the contract and has not disproved it.
//
// This is a skip and not a failure because the missing decoder is a property
// of the machine, not of Wake. It is checked explicitly, rather than left to
// surface as a confusing FileNotFoundError traceback from inside the script,
// because that traceback cost a CI debugging cycle.
func requireZstdDecoder(t *testing.T, python string) {
	t.Helper()

	if err := exec.Command(python, "-c", "import zstandard").Run(); err == nil {
		return
	}
	if _, err := exec.LookPath("zstdcat"); err == nil {
		return
	}
	t.Skip("no zstd decoder available (neither the python zstandard module " +
		"nor the zstdcat binary); the example consumer cannot decompress events")
}
