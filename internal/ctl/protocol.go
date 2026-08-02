// Package ctl is the control plane: a root-owned unix socket over which
// `wake status`, `wake trigger` and `wake watch` talk to the daemon.
//
// The protocol is newline-delimited JSON in both directions. That choice is
// deliberate: it can be driven from a shell with socat during an incident,
// when the last thing anyone wants is a bespoke binary protocol standing
// between them and the answer.
package ctl

import (
	"encoding/json"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// SocketPath is where the daemon listens by default. It sits under /run
// because it is runtime state, and the daemon creates it 0600 so that only
// root can ask for a snapshot of other people's processes.
const SocketPath = "/run/wake/wake.sock"

// Command names the requests a client may make.
type Command string

const (
	CmdStatus  Command = "status"
	CmdTrigger Command = "trigger"
	CmdWatch   Command = "watch"
)

// Request is one client request.
type Request struct {
	Command Command `json:"command"`

	// Reason accompanies CmdTrigger and is recorded verbatim in the manifest.
	Reason string `json:"reason,omitempty"`

	// Classes filters CmdWatch. Empty means every class.
	Classes []string `json:"classes,omitempty"`
	// Unit filters CmdWatch to one systemd unit.
	Unit string `json:"unit,omitempty"`
}

// Response is the daemon's reply. Exactly one of the payload fields is set,
// unless Error is, in which case none are.
type Response struct {
	Error  string         `json:"error,omitempty"`
	Status *Status        `json:"status,omitempty"`
	Result *TriggerResult `json:"trigger,omitempty"`
	// Event is one line of a watch stream. Watch responses are streamed, one
	// JSON object per line, until the client disconnects.
	Event *event.Event `json:"event,omitempty"`
}

// Status is what `wake status` prints: the honest state of the recorder,
// including everything it has lost.
type Status struct {
	Version   string        `json:"version"`
	PID       int           `json:"pid"`
	Uptime    time.Duration `json:"uptime_ns"`
	StartedAt time.Time     `json:"started_at"`

	// Ring occupancy against each of its three bounds, so that an operator
	// can see which one is actually binding.
	Events      int           `json:"ring_events"`
	MaxEvents   int           `json:"ring_max_events"`
	Bytes       int           `json:"ring_bytes"`
	MaxBytes    int           `json:"ring_max_bytes"`
	Window      time.Duration `json:"ring_window_ns"`
	OldestEvent *time.Time    `json:"ring_oldest_event,omitempty"`
	NewestEvent *time.Time    `json:"ring_newest_event,omitempty"`

	// Drops is the full per-boundary, per-class report. It is here rather
	// than summarised because a summary is how a flight recorder starts
	// lying about what it lost.
	Drops event.DropReport `json:"drops"`

	Classes       []string     `json:"classes_enabled"`
	Rules         []RuleStatus `json:"trigger_rules"`
	Snapshots     int          `json:"snapshots_on_disk"`
	SnapshotBytes int64        `json:"snapshot_bytes"`
	LastSnapshot  *time.Time   `json:"last_snapshot,omitempty"`
	ConfigHash    string       `json:"config_hash"`
}

// RuleStatus reports one trigger rule's state, including how many firings its
// cooldown has swallowed.
type RuleStatus struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	Cooldown   string     `json:"cooldown"`
	LastFired  *time.Time `json:"last_fired,omitempty"`
	Suppressed uint64     `json:"suppressed"`
}

// TriggerResult reports the outcome of a manual trigger.
type TriggerResult struct {
	Accepted bool   `json:"accepted"`
	Path     string `json:"path,omitempty"`
	Events   int    `json:"events,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Encode writes v as one JSON line, which is what makes the protocol
// shell-drivable.
func Encode(enc *json.Encoder, v any) error { return enc.Encode(v) }
