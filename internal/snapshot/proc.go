package snapshot

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Sentinel fd targets. An fd whose target could not be read is still listed
// -- the fd existing is itself evidence -- but the reason is stated in-band
// so that an operator reading fd_listing.txt can tell a racing process apart
// from a sandbox that is denying the readlink. They are bracketed so they
// cannot be confused with a real path, which is never bracketed.
const (
	fdTargetClosed     = "[closed]"
	fdTargetDenied     = "[permission denied: needs CAP_SYS_PTRACE]"
	fdTargetUnreadable = "[unreadable]"
)

// ProcCaptureSummary records whether/how a proc/ scrape went, so a reader of
// manifest.json can tell "the process was already gone by trigger time"
// (Attempted true, Found false — a normal outcome for a short-lived
// process) apart from "no scrape was attempted" (the whole field is nil).
type ProcCaptureSummary struct {
	PID int32 `json:"pid"`
	// Found is false when the process had already exited by the time the
	// scrape ran. proc/ is then absent or empty; this is expected, not an
	// error, since the ninety seconds of ring history is the point, not a
	// live process (SPEC.md §1).
	Found bool `json:"found"`
	// Files lists which of the fixed file set were successfully captured,
	// so a partial scrape (e.g. one /proc file racily disappearing) is
	// visible rather than silently incomplete.
	Files []string `json:"files"`
}

// procScrapeFiles are the plain (non-listing) files copied verbatim into
// proc/, per SPEC.md §2 goal 5: "status, limits, fdinfo list, cgroup".
// cmdline is included per the task's proc/ scope (status, limits, cgroup,
// fdinfo listing, cmdline). Every one of these is metadata about the
// process, never the contents of a file the process had open — see
// ProcSource's doc comment for why fdinfo needs special handling to
// preserve that line.
var procScrapeFiles = []string{"status", "limits", "cgroup", "cmdline"}

// ProcSource captures a triggering process's /proc footprint without ever
// reading the contents of anything the process had open. This is a hard
// privacy line (CLAUDE.md, "Privacy lines are hard requirements"): fdinfo
// is deliberately captured as a *listing* of fd names and their symlink
// targets (what /proc/<pid>/fd/<n> points to), never by opening
// /proc/<pid>/fdinfo/<n> or following the fd to read what the process
// itself had open.
type ProcSource interface {
	// Scrape returns the set of plain files to write verbatim (status,
	// limits, cgroup, cmdline — see procScrapeFiles) as a name→contents
	// map, the fd listing (fd number → symlink target), and whether the
	// process existed at all. A nil/empty return with found=false is not
	// an error: the process having already exited is expected.
	Scrape(pid int32) (files map[string][]byte, fds map[string]string, found bool, err error)
}

// OSProcSource is the production ProcSource, reading the real /proc.
type OSProcSource struct {
	// ProcRoot overrides the /proc mount point. Empty means "/proc".
	ProcRoot string
}

var _ ProcSource = (*OSProcSource)(nil)

func (s *OSProcSource) procRoot() string {
	if s.ProcRoot != "" {
		return s.ProcRoot
	}
	return "/proc"
}

// Scrape implements ProcSource.
func (s *OSProcSource) Scrape(pid int32) (map[string][]byte, map[string]string, bool, error) {
	pidDir := s.procRoot() + "/" + strconv.FormatInt(int64(pid), 10)

	if _, err := os.Stat(pidDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}

	files := make(map[string][]byte)
	for _, name := range procScrapeFiles {
		b, err := os.ReadFile(pidDir + "/" + name)
		if err != nil {
			// The process can exit at any point during the scrape (it is
			// racing the kernel, not paused for us); a file that vanishes
			// partway through is recorded as absent, not fatal.
			continue
		}
		files[name] = b
	}

	fds := make(map[string]string)
	entries, err := os.ReadDir(pidDir + "/fd")
	if err == nil {
		for _, e := range entries {
			target, err := os.Readlink(pidDir + "/fd/" + e.Name())
			if err != nil {
				target = fdTargetForError(err)
			}
			fds[e.Name()] = target
		}
	}

	return files, fds, true, nil
}

// fdTargetForError classifies a failed readlink of /proc/<pid>/fd/<n>. Two
// very different failures land here and must not be conflated. ENOENT is
// benign: the fd was closed between the readdir and the readlink, since the
// process is racing the kernel rather than paused for us. EACCES is a
// misconfiguration: readlink() on /proc/<pid>/fd/* is gated on
// PTRACE_MODE_READ, so without CAP_SYS_PTRACE every target comes back denied
// and the listing is uselessly blank while still looking like a successful
// scrape. That happened for real under the shipped systemd unit, so the
// distinction is written into the file the operator will read rather than
// swallowed.
func fdTargetForError(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fdTargetClosed
	case errors.Is(err, fs.ErrPermission):
		return fdTargetDenied
	default:
		return fdTargetUnreadable
	}
}

// writeProcDir writes the fixed-shape proc/ directory for one process
// scrape. fdListing.txt is a plain-text "<fd>\t<target>" listing rather
// than fdinfo's own key=value format, because Wake is deliberately not
// reproducing /proc/<pid>/fdinfo (which can include file offsets/flags
// that read as closer to "what the process was doing" than this package
// wants to commit to as a stable contract); the symlink target is exactly
// what SPEC.md asks for ("fdinfo list") without inviting scope creep.
func writeProcDir(fsys FS, dir string, pid int32, src ProcSource) (*ProcCaptureSummary, error) {
	summary := &ProcCaptureSummary{PID: pid}

	files, fds, found, err := src.Scrape(pid)
	if err != nil {
		return nil, fmt.Errorf("scrape proc pid %d: %w", pid, err)
	}
	summary.Found = found
	if !found {
		return summary, nil
	}

	if err := fsys.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := fsys.WriteFile(dir+"/"+name, files[name], 0o600); err != nil {
			return nil, fmt.Errorf("write proc/%s: %w", name, err)
		}
		summary.Files = append(summary.Files, name)
	}

	if len(fds) > 0 {
		fdNames := make([]string, 0, len(fds))
		for name := range fds {
			fdNames = append(fdNames, name)
		}
		slices.Sort(fdNames)

		var b strings.Builder
		for _, name := range fdNames {
			fmt.Fprintf(&b, "%s\t%s\n", name, fds[name])
		}
		if err := fsys.WriteFile(dir+"/fd_listing.txt", []byte(b.String()), 0o600); err != nil {
			return nil, fmt.Errorf("write proc/fd_listing.txt: %w", err)
		}
		summary.Files = append(summary.Files, "fd_listing.txt")
	}

	return summary, nil
}
