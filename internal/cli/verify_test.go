package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exist because `wake verify-config` once reported an unbounded
// ring and a mistyped filename as valid, and exited 0 for both.
//
// The cause is worth recording: config.Load deliberately does not validate (so
// that a zero-config `wake run` works, and so both commands share one path from
// bytes to verdict), and this command had simply never called Validate. A happy
// path check would not have found it. Exit codes are the whole contract of this
// command — the SPEC calls it "exit-code gated" so it can be relied on in
// provisioning — so they are asserted directly.

// runVerify executes the command in-process and returns its output and whether
// it reported failure. RunE's error is what Root() turns into a non-zero exit,
// so an error here is exactly a non-zero exit in the built binary.
func runVerify(t *testing.T, path string) (string, bool) {
	t.Helper()

	cmd := verifyConfigCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{path})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err != nil {
		out.WriteString(err.Error())
	}
	return out.String(), err != nil
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wake.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the test config: %v", err)
	}
	return path
}

func TestVerifyConfigAcceptsTheShippedExample(t *testing.T) {
	t.Parallel()

	// The example config is what an operator installs verbatim. If it does not
	// validate, the documented install sequence fails at the first step.
	out, failed := runVerify(t, "../../deploy/wake.example.toml")
	if failed {
		t.Fatalf("the shipped example config does not validate: %s", out)
	}
	if !strings.Contains(out, "Config hash:") {
		t.Errorf("a valid config should report its hash, got: %s", out)
	}
}

func TestVerifyConfigRejectsAMissingFile(t *testing.T) {
	t.Parallel()

	out, failed := runVerify(t, filepath.Join(t.TempDir(), "typo.toml"))
	if !failed {
		t.Fatal("a mistyped filename was reported as valid; " +
			"being told nothing would be better than being told it is fine")
	}
	if !strings.Contains(out, "does not exist") {
		t.Errorf("the error should name the problem, got: %s", out)
	}
}

// TestVerifyConfigRejectsSemanticErrors is the regression that matters: each of
// these parses as valid TOML and is nonetheless a configuration that would
// misbehave at runtime. Catching them requires Validate, not just a decode.
func TestVerifyConfigRejectsSemanticErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "ring with no bound can never bind",
			body: `[ring]
window = "0s"
max_events = 0
memory_budget_bytes = 0`,
			want: "ring",
		},
		{
			name: "unknown event class",
			body: `[classes]
connnect = true`,
			want: "conn",
		},
		{
			name: "malformed CIDR",
			body: `[filters]
cidrs = ["10.0.0.0/99"]`,
			want: "cidr",
		},
		{
			name: "relative snapshot directory",
			body: `[snapshot]
dir = "relative/path"`,
			want: "dir",
		},
		{
			name: "unparseable redaction pattern",
			body: `[[redaction.rules]]
name = "broken"
pattern = "([unclosed"`,
			want: "pattern",
		},
		{
			name: "negative cooldown",
			body: `[triggers.oom]
enabled = true
cooldown = "-5s"`,
			want: "cooldown",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, failed := runVerify(t, writeConfig(t, tc.body))
			if !failed {
				t.Fatalf("accepted an invalid config (%s); it would only be "+
					"discovered during an incident", tc.name)
			}
			if !strings.Contains(strings.ToLower(out), tc.want) {
				t.Errorf("the error should mention %q so the operator can find it; got: %s",
					tc.want, out)
			}
		})
	}
}

func TestVerifyConfigRejectsUnknownKeys(t *testing.T) {
	t.Parallel()

	// A typo in a key name would otherwise be silently ignored, leaving an
	// operator convinced they had configured something they had not.
	out, failed := runVerify(t, writeConfig(t, "[ring]\nwindwo = \"5m\"\n"))
	if !failed {
		t.Fatal("a misspelt key was accepted; the operator would believe it took effect")
	}
	if !strings.Contains(out, "windwo") {
		t.Errorf("the error should quote the offending key, got: %s", out)
	}
}

func TestVerifyConfigRejectsMalformedTOML(t *testing.T) {
	t.Parallel()

	if _, failed := runVerify(t, writeConfig(t, "this is not [ toml")); !failed {
		t.Fatal("malformed TOML was accepted")
	}
}
