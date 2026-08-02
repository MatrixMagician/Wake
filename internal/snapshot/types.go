package snapshot

import (
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// Input is everything the writer needs to build one snapshot. Callers (the
// daemon's trigger path) assemble it from state they already own — the
// frozen ring, the live Drops counters, trigger metadata, and the config
// hash — and hand it to Writer.Write. This package deliberately does not
// import internal/ring, internal/trigger or internal/config so that those
// packages can evolve independently; Input is the seam.
type Input struct {
	// Events is the frozen ring's contents for this snapshot's window. The
	// writer treats the slice as read-only and sorts a copy by Timestamp
	// (stable) before serialisation, so the on-disk "oldest first" ordering
	// guarantee holds regardless of the order the caller iterated the ring
	// in.
	Events []event.Event

	// Drops is the drop-counter report at the moment of freeze. It is
	// copied verbatim into manifest.json: the full report, not a summary,
	// so a reader can see "nothing was lost here" for every boundary and
	// class (CONTEXT.md, "Drop").
	Drops event.DropReport

	// Trigger describes why this snapshot exists.
	Trigger TriggerInfo

	// ConfigHash identifies the configuration in force when this snapshot
	// was captured (SPEC.md §4: "config is one TOML file").
	ConfigHash string
}

// TriggerInfo is the trigger metadata recorded in every manifest
// (SPEC.md §2 goal 4 lists the trigger types; goal 5 requires each snapshot
// to record type, reason, matched rule, and triggering pid/unit).
type TriggerInfo struct {
	// Type is one of "watched-process", "oom", "signal", "manual",
	// "systemd-unit-failed". Not a closed Go type here deliberately: the
	// trigger engine (internal/trigger, owned elsewhere) is the source of
	// truth for the enum, and this package must not depend on it.
	Type string `json:"type"`
	// Reason is a free-text human explanation, e.g. supplied via
	// `wake trigger --reason`.
	Reason string `json:"reason,omitempty"`
	// Rule is the name/id of the configured rule that matched, if any.
	Rule string `json:"rule,omitempty"`
	// PID is the triggering process, if the trigger is process-scoped.
	PID *int32 `json:"pid,omitempty"`
	// Unit is the triggering systemd unit, if the trigger is unit-scoped
	// (a watched-unit exit or a systemd-unit-failed trigger).
	Unit string `json:"unit,omitempty"`
	// FiredAt is when the trigger condition was observed. It seeds the
	// snapshot directory's timestamp component and manifest.window's
	// fallback when Events is empty.
	FiredAt time.Time `json:"fired_at"`
}

// RetentionSettings bounds how many snapshots, and how many total bytes of
// snapshots, are kept. Zero means unlimited for that dimension. Retention is
// applied by Prune, independently of Write, so a caller can write without
// pruning (e.g. to inspect a snapshot before deciding) or prune on a timer
// unrelated to any particular write.
type RetentionSettings struct {
	// MaxCount is the maximum number of snapshot directories to retain.
	// Zero means no count-based limit.
	MaxCount int
	// MaxTotalBytes is the maximum total on-disk size of all retained
	// snapshots, in bytes. Zero means no size-based limit.
	MaxTotalBytes int64
}

// Manifest is the serialised form of manifest.json: the single file a
// reader (e.g. Sift) opens first to learn what a snapshot contains and
// whether to trust it. See docs/snapshot-format.md for the full field-by-
// field contract.
type Manifest struct {
	// SchemaVersion is event.SchemaVersion at capture time. It governs the
	// whole snapshot, not just the event lines (SPEC.md §4).
	SchemaVersion int `json:"schema_version"`
	// ID is the snapshot's directory name, repeated here so the manifest is
	// self-identifying if copied out of its directory.
	ID string `json:"id"`
	// WakeVersion is the build-stamped version of the wake binary that
	// wrote this snapshot (internal/version.Version).
	WakeVersion string `json:"wake_version"`
	// GeneratedAt is when the manifest was written, which is after Trigger
	// fired and after the ring was frozen, but before recording resumed
	// serialising this snapshot's events (freezing is cheap and atomic —
	// see CONTEXT.md "Freeze" — so this gap is small but non-zero).
	GeneratedAt time.Time `json:"generated_at"`
	// Trigger is copied verbatim from Input.
	Trigger TriggerInfo `json:"trigger"`
	// Host is a lightweight, always-present host identity. The fuller
	// point-in-time system state (meminfo, pressure, loadavg) lives in
	// system.json; Host exists here so a manifest alone identifies which
	// machine a snapshot came from.
	Host HostInfo `json:"host"`
	// Window is the capture window: the timestamps of the first and last
	// event actually present in events.jsonl.zst.
	Window CaptureWindow `json:"capture_window"`
	// EventCount is the total number of events written.
	EventCount int `json:"event_count"`
	// EventCounts is EventCount broken down per class, including classes
	// with a zero count, mirroring event.DropReport's "zero counts are
	// included deliberately" convention (internal/event/drops.go).
	EventCounts map[string]uint64 `json:"event_counts"`
	// Drops is the full drop report at freeze time, copied verbatim from
	// Input (SPEC.md §2 goal 3 and goal 5).
	Drops event.DropReport `json:"drops"`
	// ConfigHash is copied verbatim from Input.
	ConfigHash string `json:"config_hash"`
	// Proc records whether/how the triggering process scrape succeeded, so
	// a reader can tell "no proc/ data" apart from "proc/ wasn't attempted".
	Proc *ProcCaptureSummary `json:"proc,omitempty"`
}

// HostInfo is the manifest's lightweight host identity.
type HostInfo struct {
	Hostname      string `json:"hostname"`
	KernelRelease string `json:"kernel_release"`
	Machine       string `json:"machine"` // uname -m, e.g. "x86_64"
}

// CaptureWindow is the timestamp span of events actually captured. Both
// fields are nil when Events is empty (a manual, no-events snapshot is
// valid: an operator can trigger with nothing interesting in the ring).
type CaptureWindow struct {
	First *time.Time `json:"first_event_ts,omitempty"`
	Last  *time.Time `json:"last_event_ts,omitempty"`
}
