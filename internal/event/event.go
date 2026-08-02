// Package event defines Wake's canonical event model: the single vocabulary
// shared by the decoder, the ring, the enrichment cache, the trigger engine
// and the snapshot writer.
//
// See CONTEXT.md for the binding definitions of Event, Class, Drop and
// Enrichment, and SPEC.md §4 for the serialised JSONL schema.
package event

import (
	"encoding/json"
	"time"
)

// SchemaVersion governs the layout of every serialised event and of the
// snapshot manifest. It is a public contract: bump it for any change that an
// existing reader could misinterpret.
const SchemaVersion = 1

// Class is a family of events with its own BPF program, decode path, filters
// and drop counters. Classes are independently enable/disable-able.
type Class string

const (
	ClassExec    Class = "exec"
	ClassExit    Class = "exit"
	ClassSignal  Class = "signal"
	ClassOOM     Class = "oom"
	ClassOpen    Class = "open"
	ClassConnect Class = "connect"
	// ClassGeneric carries an event whose layout the decoder did not
	// recognise. Decode is total: unknown records are retained with their raw
	// payload rather than dropped. See CLAUDE.md, "Decode is total".
	ClassGeneric Class = "generic"
)

// Classes lists every class in a stable order, for iteration in config
// validation, status output and drop accounting.
var Classes = []Class{
	ClassExec, ClassExit, ClassSignal, ClassOOM, ClassOpen, ClassConnect, ClassGeneric,
}

// Valid reports whether c is a known class.
func (c Class) Valid() bool {
	for _, k := range Classes {
		if k == c {
			return true
		}
	}
	return false
}

// Enrichment is the attribution attached to an event at snapshot time from the
// enrichment cache. Fields are best-effort: an empty value means "not known",
// never "not applicable", and is serialised as null rather than guessed at.
type Enrichment struct {
	Comm      string   `json:"comm,omitempty"`
	Ppid      int32    `json:"ppid,omitempty"`
	Ancestors []string `json:"ancestors,omitempty"` // comm chain, depth-limited, nearest first
	Cgroup    string   `json:"cgroup,omitempty"`
	Unit      string   `json:"unit,omitempty"`
	Container string   `json:"container,omitempty"`
	User      string   `json:"user,omitempty"`
}

// Event is one observed kernel occurrence. It is the only record type that
// enters the ring and the only one serialised to events.jsonl.zst.
//
// The struct is deliberately flat and union-ish rather than an interface
// hierarchy: it is serialised as a single JSONL schema, sorted by time, and
// read by foreign consumers. Class selects which optional fields are
// meaningful; absent fields are omitted rather than zero-filled.
type Event struct {
	// Common to every class.
	Timestamp time.Time `json:"ts"`
	Class     Class     `json:"class"`
	PID       int32     `json:"pid"`
	TID       int32     `json:"tid,omitempty"`
	UID       uint32    `json:"uid"`
	CgroupID  uint64    `json:"cgroup_id,omitempty"`

	// Enrichment, resolved at snapshot time.
	Enrichment

	// exec
	Filename  string   `json:"filename,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	ArgvTrunc bool     `json:"argv_truncated,omitempty"`

	// exit
	ExitCode   *int32 `json:"exit_code,omitempty"`
	ExitSignal *int32 `json:"exit_signal,omitempty"`

	// signal
	Signal     *int32 `json:"signal,omitempty"`
	SignalName string `json:"signal_name,omitempty"`
	SenderPID  *int32 `json:"sender_pid,omitempty"`

	// oom
	TotalVM     uint64 `json:"total_vm_kb,omitempty"`
	AnonRSS     uint64 `json:"anon_rss_kb,omitempty"`
	FileRSS     uint64 `json:"file_rss_kb,omitempty"`
	OOMScoreAdj *int16 `json:"oom_score_adj,omitempty"`

	// open
	Path      string `json:"path,omitempty"`
	PathTrunc bool   `json:"path_truncated,omitempty"`
	Flags     string `json:"flags,omitempty"`

	// connect
	SAddr    string `json:"saddr,omitempty"`
	DAddr    string `json:"daddr,omitempty"`
	SPort    uint16 `json:"sport,omitempty"`
	DPort    uint16 `json:"dport,omitempty"`
	Proto    string `json:"proto,omitempty"`
	OldState string `json:"old_state,omitempty"`
	NewState string `json:"new_state,omitempty"`

	// Result, for classes that have one (open, connect).
	Ret   *int64 `json:"ret,omitempty"`
	Errno string `json:"errno,omitempty"`

	// generic: the undecoded payload, retained verbatim so that nothing
	// disappears silently.
	RawKind uint32 `json:"raw_kind,omitempty"`
	Raw     []byte `json:"raw,omitempty"`

	// DecodeError explains why a record became generic, if it did.
	DecodeError string `json:"decode_error,omitempty"`
}

// Size is the event's approximate heap cost in bytes, used by the ring to
// enforce its memory budget. It is an estimate, not an exact measurement:
// the ring's memory bound is a guard rail, not an accounting ledger.
func (e *Event) Size() int {
	n := 320 // struct overhead, conservatively rounded up
	n += len(e.Filename) + len(e.Path) + len(e.Comm) + len(e.Cgroup) +
		len(e.Unit) + len(e.Container) + len(e.User) + len(e.Flags) +
		len(e.SAddr) + len(e.DAddr) + len(e.Proto) + len(e.OldState) +
		len(e.NewState) + len(e.Errno) + len(e.SignalName) + len(e.DecodeError) +
		len(e.Raw)
	for _, a := range e.Argv {
		n += len(a) + 16
	}
	for _, a := range e.Ancestors {
		n += len(a) + 16
	}
	return n
}

// MarshalJSONLine serialises the event as one JSONL line without a trailing
// newline. `wake watch` and the snapshot writer share this one path so that
// live output and persisted output can never drift (SPEC.md §10, question 4).
func (e *Event) MarshalJSONLine() ([]byte, error) { return json.Marshal(e) }
