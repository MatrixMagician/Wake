// Package decode turns raw BPF ring-buffer records into canonical events.
//
// The governing rule is that decode is total: every record produces an event.
// A record with an unknown kind, an unexpected wire version, or a length that
// does not match its class becomes a generic event carrying the raw bytes and
// an explanation, because a flight recorder that silently discards what it
// does not understand is lying to its operator.
package decode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// WireVersion mirrors WAKE_WIRE_VERSION in bpf/wake_event.h. A record carrying
// any other value is decoded generically rather than misread.
const WireVersion = 1

// Kind values mirror enum wake_kind in bpf/wake_event.h.
const (
	KindExec    uint32 = 1
	KindExit    uint32 = 2
	KindSignal  uint32 = 3
	KindOOM     uint32 = 4
	KindOpen    uint32 = 5
	KindConnect uint32 = 6
)

// Fixed sizes mirroring bpf/wake_event.h. The layout test asserts that the
// struct sizes below match the C ones byte for byte.
const (
	commLen = 16
	argvLen = 512
	pathLen = 256

	headerSize = 8 + 4 + 4 + 4 + 4 + 4 + 4 + 8 + commLen // 56
	// execSize includes 4 bytes of tail padding: the struct's alignment is 8
	// (the header's __u64 fields), and 836 bytes of content rounds to 840.
	// Verified with a C sizeof() against bpf/wake_event.h; see TestWireSizes.
	execSize    = 840
	exitSize    = headerSize + 4 + 4 + 1 + 7
	signalSize  = headerSize + 4 + 4 + 4 + 4
	oomSize     = headerSize + 8 + 8 + 8 + 8 + 2 + 6
	openSize    = headerSize + 8 + 4 + 1 + 3 + pathLen
	connectSize = headerSize + 4 + 4 + 2 + 2 + 2 + 2 + 16 + 16
)

// KindToClass maps a wire kind onto the canonical class.
func KindToClass(kind uint32) (event.Class, bool) {
	switch kind {
	case KindExec:
		return event.ClassExec, true
	case KindExit:
		return event.ClassExit, true
	case KindSignal:
		return event.ClassSignal, true
	case KindOOM:
		return event.ClassOOM, true
	case KindOpen:
		return event.ClassOpen, true
	case KindConnect:
		return event.ClassConnect, true
	default:
		return event.ClassGeneric, false
	}
}

// Clock converts a kernel boot-time nanosecond stamp into wall-clock time.
// It is an interface so that tests can decode with a fixed, checkable epoch
// rather than whatever the host booted at.
type Clock interface {
	BootTimeToWall(nsSinceBoot uint64) time.Time
}

// BootClock is the production Clock: a fixed boot instant, sampled once, plus
// the kernel's monotonic offset. Sampling once matters, because resampling
// would make identical records decode to different times.
type BootClock struct{ Boot time.Time }

// BootTimeToWall implements Clock.
func (c BootClock) BootTimeToWall(ns uint64) time.Time {
	return c.Boot.Add(time.Duration(ns)) //nolint:gosec // ns fits a Duration for any plausible uptime
}

// Decoder converts records to events. It is stateless apart from its clock, so
// it is safe for concurrent use.
type Decoder struct {
	Clock Clock
}

// New returns a Decoder using the supplied clock.
func New(c Clock) *Decoder { return &Decoder{Clock: c} }

// ErrShortRecord is reported inside a generic event when a record is too small
// to contain even a header. It is never returned to the caller, because
// returning an error would tempt the caller into dropping the record.
var ErrShortRecord = errors.New("record shorter than wake_header")

// Decode converts one ring-buffer record into an event. It never fails: a
// record it cannot interpret becomes a generic event with the raw payload and
// a DecodeError explaining why.
func (d *Decoder) Decode(rec []byte) event.Event {
	if len(rec) < headerSize {
		return d.generic(rec, 0, ErrShortRecord.Error())
	}

	kind := binary.LittleEndian.Uint32(rec[8:])
	wire := binary.LittleEndian.Uint32(rec[12:])
	ev := d.header(rec)

	if wire != WireVersion {
		return d.genericFrom(ev, rec, kind,
			fmt.Sprintf("unsupported wire version %d (want %d)", wire, WireVersion))
	}

	class, known := KindToClass(kind)
	if !known {
		return d.genericFrom(ev, rec, kind, fmt.Sprintf("unknown kind %d", kind))
	}
	ev.Class = class

	var err error
	switch kind {
	case KindExec:
		err = decodeExec(&ev, rec)
	case KindExit:
		err = decodeExit(&ev, rec)
	case KindSignal:
		err = decodeSignal(&ev, rec)
	case KindOOM:
		err = decodeOOM(&ev, rec)
	case KindOpen:
		err = decodeOpen(&ev, rec)
	case KindConnect:
		err = decodeConnect(&ev, rec)
	}
	if err != nil {
		return d.genericFrom(ev, rec, kind, err.Error())
	}
	return ev
}

// header decodes the part every record shares.
func (d *Decoder) header(rec []byte) event.Event {
	ts := binary.LittleEndian.Uint64(rec[0:])
	ev := event.Event{
		Timestamp: d.Clock.BootTimeToWall(ts),
		PID:       int32(binary.LittleEndian.Uint32(rec[16:])), //nolint:gosec // pid_t is int32
		TID:       int32(binary.LittleEndian.Uint32(rec[20:])), //nolint:gosec // pid_t is int32
		UID:       binary.LittleEndian.Uint32(rec[24:]),
		CgroupID:  binary.LittleEndian.Uint64(rec[32:]),
	}
	ev.Comm = cstring(rec[40 : 40+commLen])
	return ev
}

func (d *Decoder) generic(rec []byte, kind uint32, reason string) event.Event {
	return event.Event{
		Timestamp:   time.Now().UTC(),
		Class:       event.ClassGeneric,
		RawKind:     kind,
		Raw:         append([]byte(nil), rec...),
		DecodeError: reason,
	}
}

func (d *Decoder) genericFrom(ev event.Event, rec []byte, kind uint32, reason string) event.Event {
	ev.Class = event.ClassGeneric
	ev.RawKind = kind
	ev.Raw = append([]byte(nil), rec...)
	ev.DecodeError = reason
	return ev
}

func sizeErr(class string, got, want int) error {
	return fmt.Errorf("%s record is %d bytes, want %d", class, got, want)
}

func decodeExec(ev *event.Event, rec []byte) error {
	if len(rec) < execSize {
		return sizeErr("exec", len(rec), execSize)
	}
	off := headerSize
	ppid := binary.LittleEndian.Uint32(rec[off:])
	argvLenUsed := binary.LittleEndian.Uint32(rec[off+4:])
	trunc := rec[off+8] != 0
	off += 12

	ev.Ppid = int32(ppid) //nolint:gosec // pid_t is int32
	ev.Filename = cstring(rec[off : off+pathLen])
	off += pathLen

	if int(argvLenUsed) > argvLen {
		// Trust the buffer over the length field: a bogus length must not
		// become an out-of-range read, and the record is still worth keeping.
		argvLenUsed = argvLen
		trunc = true
	}
	ev.Argv = splitArgv(rec[off : off+int(argvLenUsed)])
	ev.ArgvTrunc = trunc
	return nil
}

func decodeExit(ev *event.Event, rec []byte) error {
	if len(rec) < exitSize {
		return sizeErr("exit", len(rec), exitSize)
	}
	off := headerSize
	code := int32(binary.LittleEndian.Uint32(rec[off:]))  //nolint:gosec // signed on the wire
	sig := int32(binary.LittleEndian.Uint32(rec[off+4:])) //nolint:gosec // signed on the wire
	ev.ExitCode = &code
	if sig != 0 {
		ev.ExitSignal = &sig
		ev.SignalName = SignalName(sig)
	}
	return nil
}

func decodeSignal(ev *event.Event, rec []byte) error {
	if len(rec) < signalSize {
		return sizeErr("signal", len(rec), signalSize)
	}
	off := headerSize
	sig := int32(binary.LittleEndian.Uint32(rec[off:]))      //nolint:gosec // signed on the wire
	sender := int32(binary.LittleEndian.Uint32(rec[off+8:])) //nolint:gosec // pid_t is int32
	ev.Signal = &sig
	ev.SignalName = SignalName(sig)
	if sender != 0 {
		ev.SenderPID = &sender
	}
	return nil
}

func decodeOOM(ev *event.Event, rec []byte) error {
	if len(rec) < oomSize {
		return sizeErr("oom", len(rec), oomSize)
	}
	off := headerSize
	ev.TotalVM = binary.LittleEndian.Uint64(rec[off:])
	ev.AnonRSS = binary.LittleEndian.Uint64(rec[off+8:])
	ev.FileRSS = binary.LittleEndian.Uint64(rec[off+16:])
	adj := int16(binary.LittleEndian.Uint16(rec[off+32:])) //nolint:gosec // signed on the wire
	ev.OOMScoreAdj = &adj
	return nil
}

func decodeOpen(ev *event.Event, rec []byte) error {
	if len(rec) < openSize {
		return sizeErr("open", len(rec), openSize)
	}
	off := headerSize
	ret := int64(binary.LittleEndian.Uint64(rec[off:]))     //nolint:gosec // signed on the wire
	flags := int32(binary.LittleEndian.Uint32(rec[off+8:])) //nolint:gosec // signed on the wire
	ev.PathTrunc = rec[off+12] != 0
	off += 16
	ev.Path = cstring(rec[off : off+pathLen])
	ev.Ret = &ret
	ev.Flags = OpenFlags(flags)
	if ret < 0 {
		ev.Errno = Errno(-ret)
	}
	return nil
}

func decodeConnect(ev *event.Event, rec []byte) error {
	if len(rec) < connectSize {
		return sizeErr("connect", len(rec), connectSize)
	}
	off := headerSize
	old := int32(binary.LittleEndian.Uint32(rec[off:]))     //nolint:gosec // signed on the wire
	newSt := int32(binary.LittleEndian.Uint32(rec[off+4:])) //nolint:gosec // signed on the wire
	ev.SPort = binary.LittleEndian.Uint16(rec[off+8:])
	ev.DPort = binary.LittleEndian.Uint16(rec[off+10:])
	family := binary.LittleEndian.Uint16(rec[off+12:])
	proto := binary.LittleEndian.Uint16(rec[off+14:])
	off += 16

	ev.OldState = TCPState(old)
	ev.NewState = TCPState(newSt)
	ev.Proto = Protocol(proto)
	ev.SAddr = addr(rec[off:off+16], family)
	ev.DAddr = addr(rec[off+16:off+32], family)

	// The tracepoint carries no errno, so the outcome is inferred from the
	// transition: leaving SYN_SENT for CLOSE is a failed connect. See
	// docs/decisions/0001-connect-via-inet-sock-set-state.md.
	if old == tcpSynSent && newSt == tcpClose {
		ev.Errno = "ECONNREFUSED_OR_TIMEOUT"
	}
	return nil
}

const (
	afInet  = 2
	afInet6 = 10
)

// addr renders a raw address of the given family. An address family we do not
// recognise yields an empty string rather than a plausible-looking wrong
// answer, because a wrong address in an incident report costs hours.
func addr(b []byte, family uint16) string {
	switch family {
	case afInet:
		a, ok := netip.AddrFromSlice(b[:4])
		if !ok {
			return ""
		}
		return a.String()
	case afInet6:
		a, ok := netip.AddrFromSlice(b[:16])
		if !ok {
			return ""
		}
		return a.Unmap().String()
	default:
		return ""
	}
}

// cstring reads a NUL-terminated string from a fixed-width field.
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// splitArgv splits the kernel's NUL-separated argv block. A trailing partial
// argument (the truncation case) is kept: half an argument is still evidence.
func splitArgv(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	s = strings.TrimRight(s, "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}
