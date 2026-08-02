package loader

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Loader is the production Source: it loads the embedded BPF objects, attaches
// the programs for the enabled classes, populates the filter maps, and pumps
// raw records onto a channel.
type Loader struct {
	objs  wakeObjects
	links []link.Link
	rb    *ringbuf.Reader

	records chan Record
	log     *slog.Logger

	closeOnce sync.Once
	closed    chan struct{}
	wg        sync.WaitGroup
}

// Load loads and attaches everything the options ask for. On any failure it
// unwinds what it has already attached, so a partial load never leaves
// programs running against a daemon that has given up.
func Load(opts Options, log *slog.Logger) (*Loader, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("loader options: %w", err)
	}
	if log == nil {
		log = slog.Default()
	}

	// Memory-locked-memory limits still bite on older kernels and in
	// containers with a low RLIMIT_MEMLOCK, and the resulting EPERM is
	// famously unhelpful, so raise it explicitly and say so if we cannot.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit (need CAP_SYS_RESOURCE, or root): %w", err)
	}

	spec, err := loadWake()
	if err != nil {
		return nil, fmt.Errorf("loading embedded BPF objects: %w", err)
	}

	// A BPF ring buffer's size is its MaxEntries, in bytes, and the kernel
	// requires a power of two.
	if m, ok := spec.Maps["events"]; ok {
		m.MaxEntries = uint32(roundUpPow2(opts.RingBufBytes)) //nolint:gosec
	}

	l := &Loader{
		records: make(chan Record, 4096),
		log:     log,
		closed:  make(chan struct{}),
	}

	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("BPF verifier rejected the programs: %+v", ve)
		}
		return nil, fmt.Errorf("loading BPF objects into the kernel: %w", err)
	}

	if err := l.configure(opts); err != nil {
		_ = l.objs.Close()
		return nil, err
	}
	if err := l.attach(opts); err != nil {
		l.detach()
		_ = l.objs.Close()
		return nil, err
	}

	l.rb, err = ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.detach()
		_ = l.objs.Close()
		return nil, fmt.Errorf("opening the BPF ring buffer: %w", err)
	}

	l.wg.Add(1)
	go l.pump()
	return l, nil
}

// wakeCfg mirrors struct wake_cfg in bpf/wake_maps.h.
type wakeCfg struct {
	SelfPID     uint64
	CgroupScope uint64
	Classes     uint32
	FilterComm  uint32
	CommIsAllow uint32
	FilterPath  uint32
	FilterPort  uint32
	_           uint32
}

func (l *Loader) configure(opts Options) error {
	cfg := wakeCfg{SelfPID: uint64(opts.SelfPID)} //nolint:gosec

	for _, c := range opts.Classes {
		cfg.Classes |= 1 << classKinds[c]
	}

	switch {
	case len(opts.CommAllow) > 0:
		cfg.FilterComm, cfg.CommIsAllow = 1, 1
		if err := l.fillComms(opts.CommAllow); err != nil {
			return err
		}
	case len(opts.CommDeny) > 0:
		cfg.FilterComm = 1
		if err := l.fillComms(opts.CommDeny); err != nil {
			return err
		}
	}

	if len(opts.CgroupPaths) > 0 {
		cfg.CgroupScope = 1
		if err := l.fillCgroups(opts.CgroupPaths); err != nil {
			return err
		}
	}

	if len(opts.PathPrefixes) > 0 {
		cfg.FilterPath = 1
		for _, p := range opts.PathPrefixes {
			var key [prefixLen]byte
			copy(key[:], p)
			if err := l.objs.PathFilter.Put(key, uint8(1)); err != nil {
				return fmt.Errorf("adding path prefix %q to the kernel filter: %w", p, err)
			}
		}
	}

	if len(opts.Ports) > 0 {
		cfg.FilterPort = 1
		for _, p := range opts.Ports {
			if err := l.objs.PortFilter.Put(p, uint8(1)); err != nil {
				return fmt.Errorf("adding port %d to the kernel filter: %w", p, err)
			}
		}
	}

	for _, s := range opts.Signals {
		if err := l.objs.SignalFilter.Put(uint32(s), uint8(1)); err != nil { //nolint:gosec
			return fmt.Errorf("adding signal %d to the kernel filter: %w", s, err)
		}
	}

	if err := l.objs.WakeConfigMap.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("publishing configuration to the kernel: %w", err)
	}
	return nil
}

func (l *Loader) fillComms(comms []string) error {
	for _, c := range comms {
		var key [commLen]byte
		copy(key[:], c)
		if err := l.objs.CommFilter.Put(key, uint8(1)); err != nil {
			return fmt.Errorf("adding comm %q to the kernel filter: %w", c, err)
		}
	}
	return nil
}

// fillCgroups resolves each configured cgroup path to its id and inserts the
// whole subtree. Userspace walks the tree because a bounded-loop ancestor walk
// in BPF is both awkward and slower; the set is small and changes rarely.
func (l *Loader) fillCgroups(paths []string) error {
	for _, p := range paths {
		root := p
		if !strings.HasPrefix(root, "/sys/fs/cgroup") {
			root = filepath.Join("/sys/fs/cgroup", root)
		}
		n := 0
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				return nil
			}
			id, idErr := cgroupID(path)
			if idErr != nil {
				// A cgroup that vanished mid-walk is normal on a busy host and
				// is not worth failing the daemon's start-up over.
				l.log.Debug("skipping cgroup", "path", path, "err", idErr)
				return nil
			}
			if putErr := l.objs.CgroupScope.Put(id, uint8(1)); putErr != nil {
				return fmt.Errorf("adding cgroup %s: %w", path, putErr)
			}
			n++
			return nil
		})
		if err != nil {
			return fmt.Errorf("scoping to cgroup %q: %w", p, err)
		}
		l.log.Debug("cgroup scope populated", "root", root, "cgroups", n)
	}
	return nil
}

// cgroupID returns the kernel's cgroup id for a path, which is the inode
// number of the cgroup directory — the same value bpf_get_current_cgroup_id
// returns.
func cgroupID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// attachment describes one program and where it hangs.
type attachment struct {
	class   string
	prog    *ebpf.Program
	attach  func(*ebpf.Program) (link.Link, error)
	summary string
}

func (l *Loader) attach(opts Options) error {
	enabled := make(map[string]bool, len(opts.Classes))
	for _, c := range opts.Classes {
		enabled[c] = true
	}

	tp := func(group, name string) func(*ebpf.Program) (link.Link, error) {
		return func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint(group, name, p, nil)
		}
	}
	raw := func(name string) func(*ebpf.Program) (link.Link, error) {
		return func(p *ebpf.Program) (link.Link, error) {
			return link.AttachTracing(link.TracingOptions{Program: p})
		}
	}

	for _, a := range []attachment{
		{"exec", l.objs.WakeExecProg, raw("sched_process_exec"), "tp_btf/sched_process_exec"},
		{"exit", l.objs.WakeExitProg, raw("sched_process_exit"), "tp_btf/sched_process_exit"},
		{"signal", l.objs.WakeSignalProg, raw("signal_deliver"), "tp_btf/signal_deliver"},
		{"oom", l.objs.WakeOomProg, raw("mark_victim"), "tp_btf/mark_victim"},
		{"open", l.objs.WakeOpenatEnter, tp("syscalls", "sys_enter_openat"), "syscalls:sys_enter_openat"},
		{"open", l.objs.WakeOpenatExit, tp("syscalls", "sys_exit_openat"), "syscalls:sys_exit_openat"},
		{"connect", l.objs.WakeInetState, tp("sock", "inet_sock_set_state"), "sock:inet_sock_set_state"},
	} {
		if !enabled[a.class] {
			continue
		}
		lk, err := a.attach(a.prog)
		if err != nil {
			return fmt.Errorf("attaching %s for class %q: %w", a.summary, a.class, err)
		}
		l.links = append(l.links, lk)
		l.log.Debug("attached", "class", a.class, "hook", a.summary)
	}

	if len(l.links) == 0 {
		return errors.New("no event classes enabled: the recorder would record nothing")
	}
	return nil
}

// pump reads raw records and forwards them. It never blocks on a slow
// consumer indefinitely: a full channel means userspace cannot keep up, which
// is a condition the ring's own drop accounting must see rather than one that
// stalls the kernel reader.
func (l *Loader) pump() {
	defer l.wg.Done()
	defer close(l.records)

	for {
		rec, err := l.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			select {
			case <-l.closed:
				return
			default:
			}
			l.log.Warn("ring buffer read failed", "err", err)
			continue
		}

		raw := make([]byte, len(rec.RawSample))
		copy(raw, rec.RawSample)

		select {
		case l.records <- Record{Raw: raw, Read: time.Now()}:
		case <-l.closed:
			return
		}
	}
}

// Records implements Source.
func (l *Loader) Records() <-chan Record { return l.records }

// KernelDrops implements Source, reading the per-class counters the BPF side
// increments when a ring-buffer reserve fails.
func (l *Loader) KernelDrops() (map[string]uint64, error) {
	out := make(map[string]uint64, len(classKinds))
	for name, kind := range classKinds {
		var v uint64
		if err := l.objs.Drops.Lookup(kind, &v); err != nil {
			return nil, fmt.Errorf("reading kernel drop counter for %q: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}

// Close implements Source. It is safe to call more than once.
func (l *Loader) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		if l.rb != nil {
			err = l.rb.Close()
		}
		l.wg.Wait()
		l.detach()
		if cerr := l.objs.Close(); cerr != nil && err == nil {
			err = cerr
		}
	})
	return err
}

func (l *Loader) detach() {
	for _, lk := range l.links {
		_ = lk.Close()
	}
	l.links = nil
}

// roundUpPow2 rounds a ring-buffer size up to the power of two the kernel
// insists on, rather than failing a load over an operator's round number.
func roundUpPow2(n int) int {
	if n <= 4096 {
		return 4096
	}
	p := 4096
	for p < n {
		p <<= 1
	}
	return p
}
