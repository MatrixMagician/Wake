package snapshot

import (
	"strings"
	"time"
)

// idTimeFormat is "RFC3339-ish" per SPEC.md §2 goal 5: RFC3339 with colons
// replaced so the timestamp is safe as a path component on every
// filesystem Wake targets (colons are legal on ext4/xfs but awkward
// elsewhere, and consistently avoiding them means one format works
// everywhere). Fractional seconds are dropped: snapshot names only need to
// be unique to the second in practice (triggers have a cooldown), and a
// shorter name is a kinder one to type in an incident.
const idTimeFormat = "20060102T150405Z"

// snapshotID returns the directory name for a snapshot triggered at t for
// the given trigger type: "<RFC3339-ish timestamp>-<trigger>" as specified
// in SPEC.md §2 goal 5 and §3. t is converted to UTC first so IDs sort
// lexically in time order regardless of the local timezone of the host that
// produced them — important because a support engineer may be comparing
// snapshots copied off several hosts in different zones.
func snapshotID(t time.Time, triggerType string) string {
	return t.UTC().Format(idTimeFormat) + "-" + sanitiseTriggerType(triggerType)
}

// sanitiseTriggerType maps a trigger type to a safe, predictable path
// component: lower-case, spaces and slashes folded to hyphens, and empty
// input replaced with "unknown" rather than producing a trailing bare
// hyphen or an empty final segment.
func sanitiseTriggerType(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "unknown"
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
	return s
}
