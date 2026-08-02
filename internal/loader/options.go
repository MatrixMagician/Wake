package loader

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Options is everything the loader needs from configuration, expressed in the
// loader's own terms. It deliberately does not import internal/config: the
// kernel-facing package should not have to change when a TOML key is renamed.
type Options struct {
	// RingBufBytes sizes the BPF ring buffer. Rounded up to a power of two,
	// which the kernel requires.
	RingBufBytes int

	// Classes enables event classes by name ("exec", "exit", ...). A class
	// that is not listed has its program left unattached, so it costs nothing.
	Classes []string

	// CgroupPaths scopes recording to these cgroup subtrees. Empty means the
	// whole system.
	CgroupPaths []string

	// CommAllow and CommDeny are mutually exclusive comm filters. Both empty
	// means no comm filtering.
	CommAllow []string
	CommDeny  []string

	// PathPrefixes filters the open class in kernel. Empty means every path.
	PathPrefixes []string

	// Ports filters the connect class by destination port. Empty means every
	// port.
	Ports []uint16

	// CIDRs filters the connect class by destination network. Applied in
	// userspace, not in kernel: an LPM-trie per address family is more BPF
	// complexity than the saving justifies at v1 volumes, and the honest
	// place to say so is here. See docs/decisions/0002-cidr-filtering.md.
	CIDRs []netip.Prefix

	// Signals is the allow list for the signal class. Recording every SIGCHLD
	// on a busy host would drown the ring, so an empty list means the signal
	// class records nothing.
	Signals []int32

	// SelfPID excludes Wake's own process, without which the recorder would
	// observe its own /proc reads and feed itself.
	SelfPID int32
}

// Validate checks the options in isolation, so that a bad configuration fails
// before any kernel resource is allocated.
func (o Options) Validate() error {
	if o.RingBufBytes < 4096 {
		return fmt.Errorf("ring buffer size %d is below the 4096-byte minimum", o.RingBufBytes)
	}
	if len(o.CommAllow) > 0 && len(o.CommDeny) > 0 {
		return errors.New("comm allow and deny lists are mutually exclusive")
	}
	for _, c := range o.Classes {
		if _, ok := classKinds[c]; !ok {
			return fmt.Errorf("unknown event class %q", c)
		}
	}
	for _, s := range o.Signals {
		if s < 1 || s > 64 {
			return fmt.Errorf("signal %d is outside the valid range 1-64", s)
		}
	}
	for _, c := range o.CommAllow {
		if len(c) > commLen-1 {
			return fmt.Errorf("comm %q exceeds the kernel's %d-byte limit", c, commLen-1)
		}
	}
	for _, c := range o.CommDeny {
		if len(c) > commLen-1 {
			return fmt.Errorf("comm %q exceeds the kernel's %d-byte limit", c, commLen-1)
		}
	}
	for _, p := range o.PathPrefixes {
		if len(p) > prefixLen {
			return fmt.Errorf("path prefix %q exceeds the in-kernel match length of %d bytes",
				p, prefixLen)
		}
	}
	return nil
}

const (
	commLen   = 16
	prefixLen = 64
)

// classKinds maps class names onto the wake_kind values the BPF side uses.
// Mirrors enum wake_kind in bpf/wake_event.h.
var classKinds = map[string]uint32{
	"exec": 1, "exit": 2, "signal": 3, "oom": 4, "open": 5, "connect": 6,
}

// Record is one raw ring-buffer record with the time it was read. The reader
// hands these to the decoder; nothing between the kernel and the decoder
// interprets the bytes.
type Record struct {
	Raw  []byte
	Read time.Time
}

// Source is the seam between the kernel and everything else. The production
// implementation is *Loader; tests use a fake that replays fixture records, so
// no unit test in Wake needs a kernel or a capability.
type Source interface {
	// Records returns the channel of raw records. It is closed when the
	// source is finished, which for the kernel source means Close was called.
	Records() <-chan Record

	// KernelDrops returns per-class kernel-side drop counts, keyed by class
	// name, read from the BPF counter map. These are absolute totals since
	// load, not deltas.
	KernelDrops() (map[string]uint64, error)

	// Close detaches everything and releases the kernel resources.
	Close() error
}
