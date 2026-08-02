package snapshot

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// SystemInfo is the serialised form of system.json: point-in-time host
// state captured at trigger time (SPEC.md §2 goal 5).
type SystemInfo struct {
	CapturedAt time.Time `json:"captured_at"`
	Uname      Uname     `json:"uname"`
	// MemInfo is /proc/meminfo verbatim as key (without the trailing
	// colon) to value-string (including any " kB" suffix), so a reader
	// gets exactly what the kernel reported without Wake guessing at
	// units or picking a subset.
	MemInfo map[string]string `json:"meminfo,omitempty"`
	// Pressure holds /proc/pressure/{cpu,memory,io} verbatim per resource,
	// each split into its "some"/"full" lines. A resource is absent if the
	// file did not exist (e.g. PSI disabled in the kernel) — that is a
	// normal, expected condition, not an error.
	Pressure map[string]PSILines `json:"pressure,omitempty"`
	// Uptime is /proc/uptime's first field: seconds since boot.
	Uptime float64 `json:"uptime_seconds"`
	// LoadAvg is /proc/loadavg's three averages.
	LoadAvg [3]float64 `json:"loadavg"`
}

// Uname is the subset of struct utsname Wake reports.
type Uname struct {
	Sysname  string `json:"sysname"`
	Nodename string `json:"nodename"`
	Release  string `json:"release"`
	Version  string `json:"version"`
	Machine  string `json:"machine"`
}

// PSILines is one /proc/pressure/<resource> file's "some" and "full" lines,
// each a map of the kernel's own field names (avg10, avg60, avg300, total)
// to their string values. Kept as strings rather than parsed floats/ints
// deliberately: this is a verbatim capture, not an interpretation, and PSI's
// field set has grown over kernel versions (e.g. "full" was added after
// "some") — passing strings through means a new field appears rather than
// getting silently dropped by a struct that does not know about it yet.
type PSILines struct {
	Some map[string]string `json:"some,omitempty"`
	Full map[string]string `json:"full,omitempty"`
}

// SystemInfoSource captures point-in-time host state. It exists so the
// writer never touches syscall.Uname or /proc directly: production code
// uses OSSystemInfoSource, tests use a fake that returns fixed data,
// keeping the writer's tests hermetic and its behaviour under real-but-
// missing files (PSI disabled, no /proc/pressure) exercised deliberately.
type SystemInfoSource interface {
	Capture() (SystemInfo, error)
}

// procResourcePressureFiles lists the resources system.json reports
// pressure for, per SPEC.md §2 goal 5 ("/proc/pressure/{cpu,memory,io} if
// present").
var procResourcePressureFiles = []string{"cpu", "memory", "io"}

// OSSystemInfoSource is the production SystemInfoSource, reading the real
// /proc and calling the real uname(2).
type OSSystemInfoSource struct {
	// ProcRoot overrides the /proc mount point. Empty means "/proc". Tests
	// set this to a t.TempDir() populated with fixture files so no real
	// kernel or privilege is required.
	ProcRoot string
	// UnameFunc overrides how uname(2) is called. Nil means the real
	// syscall. Tests override this because there is no portable way to
	// fake the syscall itself.
	UnameFunc func() (Uname, error)
}

var _ SystemInfoSource = (*OSSystemInfoSource)(nil)

func (s *OSSystemInfoSource) procRoot() string {
	if s.ProcRoot != "" {
		return s.ProcRoot
	}
	return "/proc"
}

// Capture implements SystemInfoSource.
func (s *OSSystemInfoSource) Capture() (SystemInfo, error) {
	info := SystemInfo{CapturedAt: time.Now().UTC()}

	uf := s.UnameFunc
	if uf == nil {
		uf = osUname
	}
	u, err := uf()
	if err != nil {
		return SystemInfo{}, err
	}
	info.Uname = u

	root := s.procRoot()

	if mi, err := readMemInfo(root + "/meminfo"); err == nil {
		info.MemInfo = mi
	}
	// A missing meminfo file is tolerated (best-effort capture): system.json
	// is diagnostic context, not load-bearing like the event stream or drop
	// counters, so a partial capture beats failing the whole snapshot.

	pressure := make(map[string]PSILines, len(procResourcePressureFiles))
	for _, res := range procResourcePressureFiles {
		if lines, err := readPSI(root + "/pressure/" + res); err == nil {
			pressure[res] = lines
		}
		// A missing file means PSI is disabled for this resource or this
		// kernel predates PSI — both normal, so the resource is simply
		// absent from the map rather than the capture failing.
	}
	if len(pressure) > 0 {
		info.Pressure = pressure
	}

	if up, err := readUptime(root + "/uptime"); err == nil {
		info.Uptime = up
	}
	if la, err := readLoadAvg(root + "/loadavg"); err == nil {
		info.LoadAvg = la
	}

	return info, nil
}

func readMemInfo(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only: a failed close has nothing to report

	m := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		m[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	return m, sc.Err()
}

// readPSI parses the kernel's fixed two-line PSI format, e.g.:
//
//	some avg10=0.00 avg60=0.00 avg300=0.00 total=0
//	full avg10=0.00 avg60=0.00 avg300=0.00 total=0
//
// (kernel.org Documentation/accounting/psi.rst). "full" is absent for the
// cpu resource on kernels that support it (CPU has no concept of "all tasks
// stalled" the way memory/io do), which readPSI represents by simply
// leaving PSILines.Full nil rather than erroring.
func readPSI(path string) (PSILines, error) {
	f, err := os.Open(path)
	if err != nil {
		return PSILines{}, err
	}
	defer func() { _ = f.Close() }() // read-only: a failed close has nothing to report

	var out PSILines
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		kind, kvs := fields[0], fields[1:]
		m := make(map[string]string, len(kvs))
		for _, kv := range kvs {
			k, v, ok := strings.Cut(kv, "=")
			if ok {
				m[k] = v
			}
		}
		switch kind {
		case "some":
			out.Some = m
		case "full":
			out.Full = m
		}
	}
	return out, sc.Err()
}

func readUptime(path string) (float64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, nil
	}
	return strconv.ParseFloat(fields[0], 64)
}

func readLoadAvg(path string) ([3]float64, error) {
	var out [3]float64
	b, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	fields := strings.Fields(string(b))
	for i := 0; i < 3 && i < len(fields); i++ {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return out, err
		}
		out[i] = v
	}
	return out, nil
}
