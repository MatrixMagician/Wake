//go:build integration

package loader

import (
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/decode"
	"github.com/MatrixMagician/wake/internal/event"
)

// These tests require root and a live BTF-capable kernel. They are the only
// place in Wake where a test touches the kernel; everything else uses a fake
// Source. Run them with `make integration`.

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration tests need root (or CAP_BPF+CAP_PERFMON+CAP_SYS_RESOURCE)")
	}
}

func testOptions(classes ...string) Options {
	return Options{
		RingBufBytes: 1 << 20,
		Classes:      classes,
		SelfPID:      int32(os.Getpid()), //nolint:gosec
	}
}

// TestLoadAndAttachEveryClass proves each program passes the verifier and
// binds to its hook on this kernel. This is the survey SPEC.md M1 asks for:
// a failure here names exactly which tracepoint is unavailable.
func TestLoadAndAttachEveryClass(t *testing.T) {
	requireRoot(t)
	for _, class := range []string{"exec", "exit", "signal", "oom", "open", "connect"} {
		t.Run(class, func(t *testing.T) {
			l, err := Load(testOptions(class), slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatalf("loading class %q: %v", class, err)
			}
			t.Cleanup(func() { _ = l.Close() })

			drops, err := l.KernelDrops()
			if err != nil {
				t.Fatalf("reading drop counters: %v", err)
			}
			if _, ok := drops[class]; !ok {
				t.Errorf("no drop counter wired for class %q", class)
			}
		})
	}
}

// TestExecEventEndToEnd is the M1 acceptance criterion: an exec'd fixture
// binary appears in the stream with the right argv.
func TestExecEventEndToEnd(t *testing.T) {
	requireRoot(t)

	l, err := Load(testOptions("exec"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Give the attachment a moment to settle before generating the event.
	time.Sleep(100 * time.Millisecond)

	const marker = "wake-integration-marker"
	cmd := exec.Command("/bin/echo", marker, "--second-arg")
	if err := cmd.Run(); err != nil {
		t.Fatalf("running fixture: %v", err)
	}

	d := decode.New(decode.BootClock{Boot: bootTime(t)})
	deadline := time.After(5 * time.Second)
	for {
		select {
		case rec, ok := <-l.Records():
			if !ok {
				t.Fatal("record channel closed before the exec was seen")
			}
			ev := d.Decode(rec.Raw)
			if ev.Class != event.ClassExec {
				continue
			}
			if len(ev.Argv) >= 2 && ev.Argv[1] == marker {
				if ev.Filename == "" {
					t.Error("exec event carries no filename")
				}
				if ev.PID == 0 {
					t.Error("exec event carries no pid")
				}
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for the exec event")
		}
	}
}

// TestSelfExclusion proves the recorder does not observe itself, without which
// a /proc scrape would feed the ring it is scraping for.
func TestSelfExclusion(t *testing.T) {
	requireRoot(t)

	l, err := Load(testOptions("open"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer func() { _ = l.Close() }()
	time.Sleep(100 * time.Millisecond)

	// Generate open activity from this very process.
	for range 50 {
		f, err := os.Open("/proc/self/status")
		if err == nil {
			_ = f.Close()
		}
	}

	d := decode.New(decode.BootClock{Boot: bootTime(t)})
	self := int32(os.Getpid()) //nolint:gosec
	deadline := time.After(2 * time.Second)
	for {
		select {
		case rec, ok := <-l.Records():
			if !ok {
				return
			}
			if ev := d.Decode(rec.Raw); ev.PID == self {
				t.Fatalf("wake recorded its own activity: %+v", ev)
			}
		case <-deadline:
			return // no self-events seen, which is the point
		}
	}
}

func bootTime(t *testing.T) time.Time {
	t.Helper()
	b, err := BootTime()
	if err != nil {
		t.Fatalf("boot time: %v", err)
	}
	return b
}
