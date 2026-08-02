package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/MatrixMagician/wake/internal/config"
)

// The README's worked incident is the first thing a new user copies, and it had
// silently rotted: it advertised an `exit_code` value the parser rejects
// (`any-nonzero`, which is not in the grammar) and a snapshot ID shape the
// writer does not produce. Both looked plausible, which is exactly why nobody
// noticed.
//
// Documentation that does not compile is worse than none: it costs the reader
// their trust as well as their time. These tests extract the examples from
// README.md and run them through the same code the daemon uses.

func readmePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "README.md")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cannot find README.md: %v", err)
	}
	return path
}

func readmeText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(readmePath(t))
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	return string(b)
}

// fencedBlocks returns the contents of every ```lang fenced block.
func fencedBlocks(md, lang string) []string {
	var out []string
	lines := strings.Split(md, "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "```"+lang {
			continue
		}
		var body []string
		for j := i + 1; j < len(lines); j++ {
			if strings.HasPrefix(strings.TrimSpace(lines[j]), "```") {
				i = j
				break
			}
			body = append(body, lines[j])
		}
		out = append(out, strings.Join(body, "\n"))
	}
	return out
}

// TestREADMETOMLExamplesAreValid parses every TOML block in the README as a
// Wake configuration. A reader who copies one must get a working daemon, not a
// validation error on their first attempt.
func TestREADMETOMLExamplesAreValid(t *testing.T) {
	t.Parallel()

	blocks := fencedBlocks(readmeText(t), "toml")
	if len(blocks) == 0 {
		t.Fatal("no TOML examples found in README.md; has the fence syntax changed?")
	}

	for i, block := range blocks {
		path := filepath.Join(t.TempDir(), "readme.toml")
		if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
			t.Fatalf("writing the extracted example: %v", err)
		}

		cfg, err := config.Load(path)
		if err != nil {
			t.Errorf("README TOML example %d does not parse: %v\n---\n%s", i+1, err, block)
			continue
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("README TOML example %d does not validate: %v\n---\n%s", i+1, err, block)
		}
	}
}

// TestREADMESnapshotIDsMatchTheRealFormat guards the other half of the rot: an
// ID shape that the writer never produces sends a reader looking for a
// directory that cannot exist.
func TestREADMESnapshotIDsMatchTheRealFormat(t *testing.T) {
	t.Parallel()

	// The writer's format is <YYYYMMDDTHHMMSSZ>-<trigger-type>; see
	// internal/snapshot/id.go, which this pattern deliberately mirrors rather
	// than imports, so that a change to either is caught here.
	valid := regexp.MustCompile(`^\d{8}T\d{6}Z-[a-z0-9-]+$`)

	// Anything in the README that looks like it is trying to be a snapshot ID:
	// a date-like run of digits followed by a hyphen and a word.
	candidate := regexp.MustCompile(`\b\d{8}[T-][\dTZ-]*[a-z][a-z0-9-]*\b`)

	for _, m := range candidate.FindAllString(readmeText(t), -1) {
		// Skip glob forms used in shell examples, e.g. 20260802T*.
		if strings.Contains(m, "*") {
			continue
		}
		if !valid.MatchString(m) {
			t.Errorf("README shows %q as a snapshot ID, but the writer produces "+
				"<YYYYMMDDTHHMMSSZ>-<trigger-type>; a reader would look for a "+
				"directory that cannot exist", m)
		}
	}
}

// TestREADMECommandsExist checks that every `wake <subcommand>` the README
// invokes is actually a command, so a renamed subcommand cannot leave the
// documentation pointing at nothing.
func TestREADMECommandsExist(t *testing.T) {
	t.Parallel()

	known := map[string]bool{}
	for _, c := range Root().Commands() {
		known[c.Name()] = true
		for _, sub := range c.Commands() {
			known[c.Name()+" "+sub.Name()] = true
		}
	}

	// Require at least two letters, so the version string in sample output
	// ("wake v0.1.0 (pid ...)") is not mistaken for a subcommand.
	re := regexp.MustCompile(`\bwake ([a-z][a-z-]+)(?: ([a-z][a-z-]+))?`)
	for _, m := range re.FindAllStringSubmatch(readmeText(t), -1) {
		name := m[1]
		if name == "version" || name == "help" {
			continue
		}
		if !known[name] {
			t.Errorf("README invokes `wake %s`, which is not a command", name)
			continue
		}
		// Only check a second word when it is genuinely a subcommand of the
		// first, rather than a flag or prose.
		if m[2] != "" && known[name+" "+m[2]] {
			continue
		}
	}
}
