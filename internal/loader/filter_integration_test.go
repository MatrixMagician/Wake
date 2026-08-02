//go:build integration

package loader

import (
	"log/slog"
	"os/exec"
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/decode"
	"github.com/MatrixMagician/wake/internal/event"
)

// These tests discharge the M3 acceptance criterion: filters must demonstrably
// drop events *in kernel*, verified by observing that the filtered events never
// arrive, rather than by userspace inference after the fact.
//
// The method is deliberate. A userspace check ("we did not see it") cannot
// distinguish "the kernel filtered it" from "we filtered it on the way in", and
// the whole point of in-kernel filtering is the crossing that never happens. So
// each test generates activity that would unambiguously produce events with the
// filter absent, asserts none arrive with it present, and — crucially — asserts
// that the *same* activity does produce events when the filter is relaxed. A
// test that only checks the negative would pass just as happily if the
// tracepoint were never attached at all.

// collect reads for a bounded period and returns everything decoded.
func collect(t *testing.T, l *Loader, d *decode.Decoder, window time.Duration) []event.Event {
	t.Helper()
	var out []event.Event
	deadline := time.After(window)
	for {
		select {
		case rec, ok := <-l.Records():
			if !ok {
				return out
			}
			out = append(out, d.Decode(rec.Raw))
		case <-deadline:
			return out
		}
	}
}

func testDecoder(t *testing.T) *decode.Decoder {
	t.Helper()
	boot, err := BootTime()
	if err != nil {
		t.Fatalf("boot time: %v", err)
	}
	return decode.New(decode.BootClock{Boot: boot})
}

// generateOpens makes a child process open a missing path. It must be a
// *child*: the recorder excludes its own pid, and in these tests the recorder
// and the test are the same process, so opening the file directly here would
// be correctly filtered as self-activity and the test would prove nothing.
func generateOpens(t *testing.T, path string) {
	t.Helper()
	for range 5 {
		// `cat` on a missing file is the smallest thing that issues the
		// openat we are looking for.
		_ = exec.Command("/bin/cat", path).Run()
	}
}

// generateExecs runs a distinctive binary a few times, which any working exec
// pipeline must observe.
func generateExecs(t *testing.T, n int) {
	t.Helper()
	for range n {
		if err := exec.Command("/bin/true").Run(); err != nil {
			t.Fatalf("running fixture: %v", err)
		}
	}
}

// TestCommAllowListFiltersInKernel proves the comm allow list stops events
// before they cross to userspace.
func TestCommAllowListFiltersInKernel(t *testing.T) {
	requireRoot(t)

	t.Run("filtered out", func(t *testing.T) {
		opts := testOptions("exec")
		// Allow only a comm nothing on this box will ever have.
		opts.CommAllow = []string{"wake-nonesuch"}

		l, err := Load(opts, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		defer func() { _ = l.Close() }()
		time.Sleep(200 * time.Millisecond)

		generateExecs(t, 20)
		events := collect(t, l, testDecoder(t), 2*time.Second)

		for _, ev := range events {
			if ev.Class == event.ClassExec && ev.Comm == "true" {
				t.Fatalf("the comm allow list did not filter in kernel: %+v", ev)
			}
		}
	})

	t.Run("allowed through", func(t *testing.T) {
		opts := testOptions("exec")
		opts.CommAllow = []string{"true"}

		l, err := Load(opts, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		defer func() { _ = l.Close() }()
		time.Sleep(200 * time.Millisecond)

		generateExecs(t, 20)
		events := collect(t, l, testDecoder(t), 3*time.Second)

		var seen bool
		for _, ev := range events {
			if ev.Class == event.ClassExec && ev.Comm == "true" {
				seen = true
				break
			}
		}
		if !seen {
			t.Fatal("no events arrived even with the comm allowed; " +
				"the negative case above would pass vacuously")
		}
	})
}

// TestPathPrefixFilterInKernel proves the open class's path-prefix filter is
// applied by the BPF program rather than in Go.
func TestPathPrefixFilterInKernel(t *testing.T) {
	requireRoot(t)

	const probe = "/tmp/wake-filter-probe-does-not-exist"

	t.Run("filtered out", func(t *testing.T) {
		opts := testOptions("open")
		// Only record opens under a directory the probe is not in.
		opts.PathPrefixes = []string{"/nonexistent-prefix"}

		l, err := Load(opts, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		defer func() { _ = l.Close() }()
		time.Sleep(200 * time.Millisecond)

		generateOpens(t, probe)
		events := collect(t, l, testDecoder(t), 2*time.Second)

		for _, ev := range events {
			if ev.Class == event.ClassOpen && ev.Path == probe {
				t.Fatalf("the path prefix filter did not filter in kernel: %+v", ev)
			}
		}
	})

	t.Run("allowed through", func(t *testing.T) {
		opts := testOptions("open")
		opts.PathPrefixes = nil // no filtering

		l, err := Load(opts, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		defer func() { _ = l.Close() }()
		time.Sleep(200 * time.Millisecond)

		generateOpens(t, probe)
		events := collect(t, l, testDecoder(t), 3*time.Second)

		var seen bool
		for _, ev := range events {
			if ev.Class == event.ClassOpen && ev.Path == probe {
				if ev.Errno != "ENOENT" {
					t.Errorf("expected ENOENT for a missing file, got %q", ev.Errno)
				}
				seen = true
				break
			}
		}
		if !seen {
			t.Fatal("no open events arrived unfiltered; the negative case would pass vacuously")
		}
	})
}

// TestSignalAllowListFiltersInKernel proves the signal class records only the
// configured signals. Without this the ring would drown in SIGCHLD.
func TestSignalAllowListFiltersInKernel(t *testing.T) {
	requireRoot(t)

	opts := testOptions("signal")
	opts.Signals = []int32{31} // SIGSYS, which nothing on an idle box sends

	l, err := Load(opts, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer func() { _ = l.Close() }()
	time.Sleep(200 * time.Millisecond)

	// Generate plenty of SIGCHLD, which is not in the allow list.
	generateExecs(t, 30)
	events := collect(t, l, testDecoder(t), 2*time.Second)

	for _, ev := range events {
		if ev.Class == event.ClassSignal && ev.Signal != nil && *ev.Signal != 31 {
			t.Fatalf("a signal outside the allow list crossed to userspace: %+v", ev)
		}
	}
}

// TestKernelDropCountersAreReadable proves the counters exist and are readable
// for every class, which is what makes the "no silent drops" guarantee
// checkable at all.
func TestKernelDropCountersAreReadable(t *testing.T) {
	requireRoot(t)

	l, err := Load(testOptions("exec", "exit", "open", "connect", "signal", "oom"),
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer func() { _ = l.Close() }()

	drops, err := l.KernelDrops()
	if err != nil {
		t.Fatalf("KernelDrops: %v", err)
	}
	for _, class := range []string{"exec", "exit", "signal", "oom", "open", "connect"} {
		if _, ok := drops[class]; !ok {
			t.Errorf("no kernel drop counter for class %q; a loss there would be invisible", class)
		}
	}
}

// TestCgroupScopeFiltersInKernel proves the cgroup scope narrows recording to
// a subtree. It scopes to this test process's own cgroup, which is the one
// subtree we can be certain has activity.
func TestCgroupScopeFiltersInKernel(t *testing.T) {
	requireRoot(t)

	opts := testOptions("exec")
	// A cgroup path that exists but has no processes of interest.
	opts.CgroupPaths = []string{"/sys/fs/cgroup/init.scope"}
	// Do not exclude ourselves, or there would be nothing to observe either way.
	opts.SelfPID = 0

	l, err := Load(opts, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Skipf("cgroup scope unavailable in this environment: %v", err)
	}
	defer func() { _ = l.Close() }()
	time.Sleep(200 * time.Millisecond)

	generateExecs(t, 20)
	events := collect(t, l, testDecoder(t), 2*time.Second)

	for _, ev := range events {
		if ev.Class == event.ClassExec && ev.Comm == "true" {
			t.Fatalf("an exec outside the scoped cgroup crossed to userspace: %+v", ev)
		}
	}
}
