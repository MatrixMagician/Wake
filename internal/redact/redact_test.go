package redact

import (
	"strings"
	"testing"

	"github.com/MatrixMagician/wake/internal/config"
	"github.com/MatrixMagician/wake/internal/event"
)

func newRedactor(t *testing.T, cfg config.Redaction) *Redactor {
	t.Helper()
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// mustNotContain marshals e and fails the test if want appears anywhere in
// the resulting bytes. This is the load-bearing assertion the task asks
// for: masked values must never survive to the serialised form, not just
// look absent when printed with %+v.
func mustNotContain(t *testing.T, e *event.Event, want string) []byte {
	t.Helper()
	b, err := e.MarshalJSONLine()
	if err != nil {
		t.Fatalf("MarshalJSONLine: %v", err)
	}
	if strings.Contains(string(b), want) {
		t.Fatalf("secret %q survived serialisation: %s", want, b)
	}
	return b
}

func TestNilRedactorIsNoOp(t *testing.T) {
	var r *Redactor
	e := &event.Event{Argv: []string{"secret"}}
	r.Redact(e) // must not panic
	if e.Argv[0] != "secret" {
		t.Fatal("nil Redactor must not mutate the event")
	}
}

func TestDefaultRulesMaskAWSAccessKeyID(t *testing.T) {
	r := newRedactor(t, config.Redaction{UseDefaultRules: true})
	e := &event.Event{Class: event.ClassExec, Argv: []string{"env", "AKIAIOSFODNN7EXAMPLE"}}
	r.Redact(e)
	mustNotContain(t, e, "AKIAIOSFODNN7EXAMPLE")
	if !strings.Contains(e.Argv[1], "REDACTED:aws-access-key-id") {
		t.Fatalf("expected named marker, got %q", e.Argv[1])
	}
}

func TestDefaultRulesMaskBearerToken(t *testing.T) {
	r := newRedactor(t, config.Redaction{UseDefaultRules: true})
	e := &event.Event{Argv: []string{"curl", "-H", "Authorization: Bearer abcdef123456.xyz"}}
	r.Redact(e)
	mustNotContain(t, e, "abcdef123456.xyz")
}

func TestDefaultRulesMaskPasswordFlagInline(t *testing.T) {
	r := newRedactor(t, config.Redaction{UseDefaultRules: true})
	e := &event.Event{Argv: []string{"mysql", "--password=hunter2"}}
	r.Redact(e)
	mustNotContain(t, e, "hunter2")
	if !strings.Contains(e.Argv[1], "REDACTED:password-flag-inline") {
		t.Fatalf("got %q", e.Argv[1])
	}
}

// TestSecretSpanningArgvEntries covers the case where a flag and its value
// are two separate argv entries, e.g. `mysql -p hunter2`: no single-entry
// regex can see both halves, so the value must be masked wholesale once its
// preceding flag is recognised.
func TestSecretSpanningArgvEntries(t *testing.T) {
	r := newRedactor(t, config.Redaction{UseDefaultRules: true})
	e := &event.Event{Argv: []string{"mysql", "-p", "hunter2", "-u", "root"}}
	r.Redact(e)
	mustNotContain(t, e, "hunter2")
	if !strings.Contains(e.Argv[2], "REDACTED:password-flag-value") {
		t.Fatalf("expected value entry redacted, got %q", e.Argv[2])
	}
	// The flag itself and unrelated entries are untouched.
	if e.Argv[0] != "mysql" || e.Argv[1] != "-p" || e.Argv[3] != "-u" || e.Argv[4] != "root" {
		t.Fatalf("unrelated argv entries must be untouched: %v", e.Argv)
	}
}

func TestSecretSpanningArgvEntriesLongFlag(t *testing.T) {
	r := newRedactor(t, config.Redaction{UseDefaultRules: true})
	e := &event.Event{Argv: []string{"tool", "--token", "sk_live_abc123"}}
	r.Redact(e)
	mustNotContain(t, e, "sk_live_abc123")
}

func TestDefaultRulesMaskPrivateKeyPath(t *testing.T) {
	r := newRedactor(t, config.Redaction{UseDefaultRules: true})
	e := &event.Event{Class: event.ClassOpen, Path: "/home/alice/.ssh/id_ed25519"}
	r.Redact(e)
	mustNotContain(t, e, "id_ed25519")
}

func TestMaskHomeUsernames(t *testing.T) {
	r := newRedactor(t, config.Redaction{MaskHomeUsernames: true})
	e := &event.Event{Path: "/home/alice/reports/q3.csv"}
	r.Redact(e)
	mustNotContain(t, e, "alice")
	if !strings.Contains(e.Path, "REDACTED:home-username") {
		t.Fatalf("got %q", e.Path)
	}
	if !strings.HasSuffix(e.Path, "/reports/q3.csv") {
		t.Fatalf("rest of the path must be preserved: %q", e.Path)
	}
}

func TestMaskHomeUsernamesDisabledByDefault(t *testing.T) {
	r := newRedactor(t, config.Redaction{})
	e := &event.Event{Path: "/home/alice/reports/q3.csv"}
	r.Redact(e)
	if !strings.Contains(e.Path, "alice") {
		t.Fatalf("expected username preserved when mask_home_usernames is off, got %q", e.Path)
	}
}

func TestCustomRuleAppliesToConfiguredTargetOnly(t *testing.T) {
	cfg := config.Redaction{
		Rules: []config.RedactionRule{
			{Name: "internal-token", Pattern: `tok_[A-Za-z0-9]{6}`, Targets: []string{"argv"}},
		},
	}
	r := newRedactor(t, cfg)
	e := &event.Event{
		Argv: []string{"app", "tok_abc123"},
		Path: "/var/log/tok_abc123.log", // same-shaped string, but path is not a configured target
	}
	r.Redact(e)
	if strings.Contains(e.Argv[1], "tok_abc123") {
		t.Fatalf("argv should have been redacted: %q", e.Argv[1])
	}
	if !strings.Contains(e.Path, "tok_abc123") {
		t.Fatalf("path was not a configured target and must be untouched: %q", e.Path)
	}
}

func TestCustomRuleTargetAll(t *testing.T) {
	cfg := config.Redaction{
		Rules: []config.RedactionRule{
			{Name: "internal-token", Pattern: `tok_[A-Za-z0-9]{6}`, Targets: []string{"all"}},
		},
	}
	r := newRedactor(t, cfg)
	e := &event.Event{Argv: []string{"tok_abc123"}, Path: "/x/tok_abc123", Filename: "tok_abc123"}
	r.Redact(e)
	mustNotContain(t, e, "tok_abc123")
}

func TestEmptyPatternRuleIsNoOp(t *testing.T) {
	cfg := config.Redaction{
		Rules: []config.RedactionRule{{Name: "empty", Pattern: ""}},
	}
	r := newRedactor(t, cfg)
	e := &event.Event{Argv: []string{"hello", "world"}}
	r.Redact(e)
	if e.Argv[0] != "hello" || e.Argv[1] != "world" {
		t.Fatalf("empty-pattern rule must not mangle argv, got %v", e.Argv)
	}
}

// TestRegexThatMatchesEverything proves a pathological ".*"-style pattern
// still produces a serialisable, secret-free result rather than corrupting
// the event or panicking - New/Redact must survive an operator's overly
// broad custom rule.
func TestRegexThatMatchesEverything(t *testing.T) {
	cfg := config.Redaction{
		Rules: []config.RedactionRule{{Name: "everything", Pattern: ".*", Targets: []string{"argv"}}},
	}
	r := newRedactor(t, cfg)
	e := &event.Event{Argv: []string{"super-secret-value"}}
	r.Redact(e)
	mustNotContain(t, e, "super-secret-value")
}

// TestOverlappingMatches exercises two rules that both match overlapping
// substrings of the same argv entry: the second rule's regex runs against
// the first rule's already-substituted output, so it must not panic or
// reintroduce the secret, and the raw secret must not survive.
func TestOverlappingMatches(t *testing.T) {
	cfg := config.Redaction{
		Rules: []config.RedactionRule{
			{Name: "outer", Pattern: `secret-\w+-token`, Targets: []string{"argv"}},
			{Name: "inner", Pattern: `\w+-token`, Targets: []string{"argv"}},
		},
	}
	r := newRedactor(t, cfg)
	e := &event.Event{Argv: []string{"secret-abc-token"}}
	r.Redact(e)
	mustNotContain(t, e, "secret-abc-token")
}

func TestRedactionMarkerNamesFiringRule(t *testing.T) {
	cfg := config.Redaction{
		Rules: []config.RedactionRule{{Name: "my-rule", Pattern: `boom`, Targets: []string{"argv"}}},
	}
	r := newRedactor(t, cfg)
	e := &event.Event{Argv: []string{"kaboom"}}
	r.Redact(e)
	if e.Argv[0] != "ka[REDACTED:my-rule]" {
		t.Fatalf("expected named marker in place, got %q", e.Argv[0])
	}
}

func TestMultipleRulesFireOnSameEntry(t *testing.T) {
	cfg := config.Redaction{
		Rules: []config.RedactionRule{
			{Name: "rule-a", Pattern: `AAA`, Targets: []string{"argv"}},
			{Name: "rule-b", Pattern: `BBB`, Targets: []string{"argv"}},
		},
	}
	r := newRedactor(t, cfg)
	e := &event.Event{Argv: []string{"AAA-BBB"}}
	r.Redact(e)
	mustNotContain(t, e, "AAA")
	mustNotContain(t, e, "BBB")
}

func TestNewRejectsUncompilableCustomPattern(t *testing.T) {
	_, err := New(config.Redaction{Rules: []config.RedactionRule{{Name: "bad", Pattern: "["}}})
	if err == nil {
		t.Fatal("expected error for uncompilable pattern")
	}
}

func TestNewRejectsUnknownTarget(t *testing.T) {
	_, err := New(config.Redaction{
		Rules: []config.RedactionRule{{Name: "x", Pattern: "a", Targets: []string{"body"}}},
	})
	if err == nil {
		t.Fatal("expected error for unknown target")
	}
}

func TestRedactHandlesEmptyEvent(t *testing.T) {
	r := newRedactor(t, config.Redaction{UseDefaultRules: true})
	e := &event.Event{}
	r.Redact(e) // must not panic on zero-value fields
	if _, err := e.MarshalJSONLine(); err != nil {
		t.Fatalf("MarshalJSONLine on zero event: %v", err)
	}
}

func TestFilenameFieldRedacted(t *testing.T) {
	r := newRedactor(t, config.Redaction{UseDefaultRules: true})
	e := &event.Event{Filename: "/home/bob/.ssh/id_rsa"}
	r.Redact(e)
	mustNotContain(t, e, "id_rsa")
}

func TestGenericTokenFlagInlineArgv(t *testing.T) {
	r := newRedactor(t, config.Redaction{UseDefaultRules: true})
	e := &event.Event{Argv: []string{"deploy", "--api-key=sk_live_51H8xyz"}}
	r.Redact(e)
	mustNotContain(t, e, "sk_live_51H8xyz")
}
