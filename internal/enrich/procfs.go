// procfs.go implements the ProcSource interface: a real implementation that
// reads the live /proc filesystem, and an in-memory fake for tests, so that
// package enrich's own tests need never touch a real kernel or a real
// /proc/<pid> (CLAUDE.md: "unit tests never need privileges").
package enrich

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// ProcfsSource is the production ProcSource, reading /proc/<pid>/status and
// /proc/<pid>/cgroup directly. Root is the procfs mount point, overridable
// only for this package's own tests (via testdata fixtures laid out to look
// like a /proc tree); production code should always use NewProcfsSource,
// which fixes Root to "/proc".
type ProcfsSource struct {
	Root string
}

// NewProcfsSource returns a ProcSource reading the real /proc filesystem.
func NewProcfsSource() *ProcfsSource { return &ProcfsSource{Root: "/proc"} }

// Status reads comm and ppid from /proc/<pid>/status. comm here is /proc's
// "Name:" field, which the kernel truncates to 15 bytes — shorter than
// event.Event's own Comm when it came from the wire header, but a reasonable
// best-effort fallback for a pid Wake never observed directly.
func (s *ProcfsSource) Status(pid int32) (comm string, ppid int32, ok bool) {
	f, err := os.Open(s.Root + "/" + strconv.Itoa(int(pid)) + "/status")
	if err != nil {
		return "", 0, false
	}
	defer func() { _ = f.Close() }() // read-only: a failed close has nothing to report

	sc := bufio.NewScanner(f)
	var haveName, havePPid bool
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			haveName = true
		case strings.HasPrefix(line, "PPid:"):
			if v, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), 10, 32); err == nil {
				ppid = int32(v)
				havePPid = true
			}
		}
	}
	return comm, ppid, haveName && havePPid
}

// Cgroup reads /proc/<pid>/cgroup and returns the unified (cgroup v2) entry,
// the "0::<path>" line, since Wake's reference platform (Fedora, SPEC.md §1)
// runs cgroup v2 unified hierarchy exclusively. A hybrid/legacy v1 host with
// no unified line yields ok=false rather than guessing at a v1 controller's
// path, which need not correspond to the systemd-managed hierarchy at all.
func (s *ProcfsSource) Cgroup(pid int32) (path string, ok bool) {
	f, err := os.Open(s.Root + "/" + strconv.Itoa(int(pid)) + "/cgroup")
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }() // read-only: a failed close has nothing to report

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if p, found := strings.CutPrefix(line, "0::"); found {
			return p, true
		}
	}
	return "", false
}

// User resolves uid via /etc/passwd, read directly rather than through
// os/user: os/user's cgo path shells out to NSS, which is more than this
// narrow lookup needs and behaves inconsistently across the static-binary
// build SPEC.md §2 goal 8 requires. A uid absent from /etc/passwd (a
// container's uid observed from the host, for instance) correctly yields
// ok=false rather than a fabricated name.
func (s *ProcfsSource) User(uid uint32) (name string, ok bool) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }() // read-only: a failed close has nothing to report

	target := strconv.FormatUint(uint64(uid), 10)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == target {
			return fields[0], true
		}
	}
	return "", false
}

// FakeSource is an in-memory ProcSource double for tests: no real /proc
// touched, ever. Populate the maps directly; a pid or uid absent from the
// relevant map correctly reports ok=false, exercising the same "unknown, not
// guessed" path production code takes for a genuinely gone process.
type FakeSource struct {
	StatusByPID map[int32]FakeStatus
	CgroupByPID map[int32]string
	Users       map[uint32]string
}

// FakeStatus is one FakeSource process record.
type FakeStatus struct {
	Comm string
	PPid int32
}

// NewFakeSource returns an empty FakeSource ready for tests to populate.
func NewFakeSource() *FakeSource {
	return &FakeSource{
		StatusByPID: make(map[int32]FakeStatus),
		CgroupByPID: make(map[int32]string),
		Users:       make(map[uint32]string),
	}
}

func (f *FakeSource) Status(pid int32) (comm string, ppid int32, ok bool) {
	s, ok := f.StatusByPID[pid]
	if !ok {
		return "", 0, false
	}
	return s.Comm, s.PPid, true
}

func (f *FakeSource) Cgroup(pid int32) (path string, ok bool) {
	p, ok := f.CgroupByPID[pid]
	return p, ok
}

func (f *FakeSource) User(uid uint32) (name string, ok bool) {
	n, ok := f.Users[uid]
	return n, ok
}
