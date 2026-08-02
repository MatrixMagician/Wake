package redact

import "regexp"

// defaultRules returns internal/redact's built-in patterns for common
// secrets that turn up in argv and paths on a typical host. These are
// enabled whenever config.Redaction.UseDefaultRules is true (the config
// default), on top of whatever custom rules an operator adds.
//
// Deliberately conservative: false positives (over-redaction) cost a support
// engineer a follow-up question; false negatives (a leaked secret) cost a
// security incident. Patterns here favour catching the secret over
// preserving debuggability.
func defaultRules() []rule {
	return []rule{
		{
			name:    "aws-access-key-id",
			re:      regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			targets: targetAll,
		},
		{
			name: "aws-secret-access-key",
			// A 40-char base64-alphabet string is the AWS secret key shape;
			// it has no fixed prefix, so this only fires when a rule or
			// environment naming convention puts it right after
			// "aws_secret_access_key" style text, keeping false positives
			// down versus matching any 40-char token anywhere.
			re:      regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
			targets: targetAll,
		},
		{
			name:    "bearer-token",
			re:      regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*`),
			targets: targetAll,
		},
		{
			name:    "authorization-header",
			re:      regexp.MustCompile(`(?i)authorization:\s*\S+`),
			targets: targetAll,
		},
		{
			name: "password-flag-inline",
			// Catches "--password=secret", "-password=secret",
			// "--pass=secret" style inline assignment. The bare-flag form
			// ("-p secret" with the value as a *separate* argv entry) is
			// handled by defaultFlagValueRules instead, since a single
			// per-entry regex cannot see across entries.
			re:      regexp.MustCompile(`(?i)(--?(password|passwd|pass|pwd)=)\S+`),
			targets: targetArgv,
		},
		{
			name:    "private-key-path",
			re:      regexp.MustCompile(`(?i)\S*/(id_(rsa|dsa|ecdsa|ed25519)|[\w.\-]+\.pem|[\w.\-]+\.key)\b`),
			targets: targetAll,
		},
		{
			name:    "generic-token-flag-inline",
			re:      regexp.MustCompile(`(?i)(--?(token|api[_-]?key|secret)=)\S+`),
			targets: targetArgv,
		},
	}
}

// defaultFlagValueRules matches a bare flag argv entry whose *next* argv
// entry is the secret value (e.g. ["mysql", "-p", "hunter2"]).
func defaultFlagValueRules() []flagValueRule {
	return []flagValueRule{
		{name: "password-flag-value", flagRe: regexp.MustCompile(`^(?i)(--?(password|passwd|pass|pwd|p))$`)},
		{name: "token-flag-value", flagRe: regexp.MustCompile(`^(?i)(--?(token|api[_-]?key|secret))$`)},
	}
}

// homeUsernameRe matches the username segment of a "/home/<user>" path,
// used only when config.Redaction.MaskHomeUsernames is set.
var homeUsernameRe = regexp.MustCompile(`/home/[^/\s]+`)
