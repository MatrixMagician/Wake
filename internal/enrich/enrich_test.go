package enrich

import (
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

func TestObserveExecThenResolve(t *testing.T) {
	src := NewFakeSource()
	src.Users[1000] = "alice"
	c := New(100, 4, src)

	c.Observe(event.Event{
		Class: event.ClassExec,
		PID:   42,
		UID:   1000,
		Enrichment: event.Enrichment{
			Comm: "smtpd",
			Ppid: 7,
		},
	})
	// exec never provided a cgroup on the wire (only cgroup_id); Observe
	// must consult the fallback procfs cgroup lookup for the path.
	src.CgroupByPID[42] = "/system.slice/mstr.service"

	// Re-observe now that the fake procfs reflects the cgroup: this models
	// the real ordering where the decoder has already resolved Comm/Ppid
	// from the wire header but cgroup path still comes from a source read.
	c.Observe(event.Event{
		Class: event.ClassExec,
		PID:   42,
		UID:   1000,
		Enrichment: event.Enrichment{
			Comm: "smtpd",
			Ppid: 7,
		},
	})

	e := &event.Event{PID: 42, UID: 1000}
	c.Resolve(e)

	if e.Comm != "smtpd" {
		t.Errorf("Comm = %q, want smtpd", e.Comm)
	}
	if e.Ppid != 7 {
		t.Errorf("Ppid = %d, want 7", e.Ppid)
	}
	if e.Cgroup != "/system.slice/mstr.service" {
		t.Errorf("Cgroup = %q", e.Cgroup)
	}
	if e.Unit != "mstr.service" {
		t.Errorf("Unit = %q, want mstr.service", e.Unit)
	}
	if e.User != "alice" {
		t.Errorf("User = %q, want alice", e.User)
	}
}

// TestExitedProcessStaysAttributable is the scenario SPEC.md §2 goal 6 names
// explicitly: a process that exited 30s ago must still be attributable in a
// snapshot, because the cache holds entries by capacity, not liveness.
func TestExitedProcessStaysAttributable(t *testing.T) {
	src := NewFakeSource()
	c := New(100, 0, src)

	c.Observe(event.Event{
		Class:      event.ClassExec,
		PID:        99,
		Enrichment: event.Enrichment{Comm: "worker", Ppid: 1},
	})
	src.CgroupByPID[99] = "/system.slice/worker.service"
	c.Observe(event.Event{
		Class:      event.ClassExec,
		PID:        99,
		Enrichment: event.Enrichment{Comm: "worker", Ppid: 1},
	})

	code := int32(1)
	c.Observe(event.Event{
		Class:    event.ClassExit,
		PID:      99,
		ExitCode: &code,
	})

	// Now simulate the process having actually exited: the fake procfs no
	// longer has anything for pid 99 at all (as real /proc would not).
	delete(src.StatusByPID, 99)
	delete(src.CgroupByPID, 99)

	// "30 seconds later" a trigger fires and a snapshot resolves the event
	// that referenced this now-long-gone pid.
	e := &event.Event{PID: 99}
	c.Resolve(e)

	if e.Comm != "worker" {
		t.Errorf("Comm = %q, want worker (cache must survive process exit)", e.Comm)
	}
	if e.Cgroup != "/system.slice/worker.service" {
		t.Errorf("Cgroup = %q", e.Cgroup)
	}
	if e.Unit != "worker.service" {
		t.Errorf("Unit = %q, want worker.service", e.Unit)
	}
}

// TestResolveFallsBackToProcfsForUnobservedPID covers a live process present
// when the daemon started: Observe never saw it (no exec/exit event, since
// it started before Wake did), so Resolve must fall back to the injected
// procfs source rather than leaving the enrichment empty.
func TestResolveFallsBackToProcfsForUnobservedPID(t *testing.T) {
	src := NewFakeSource()
	src.StatusByPID[555] = FakeStatus{Comm: "sshd", PPid: 1}
	src.CgroupByPID[555] = "/system.slice/sshd.service"
	c := New(10, 2, src)

	e := &event.Event{PID: 555}
	c.Resolve(e)

	if e.Comm != "sshd" {
		t.Errorf("Comm = %q, want sshd", e.Comm)
	}
	if e.Unit != "sshd.service" {
		t.Errorf("Unit = %q, want sshd.service", e.Unit)
	}

	// A second Resolve for the same pid must be served from cache now, not
	// hit the fake source again — verified indirectly by removing the
	// source entry and confirming the enrichment still comes back correct.
	delete(src.StatusByPID, 555)
	delete(src.CgroupByPID, 555)
	e2 := &event.Event{PID: 555}
	c.Resolve(e2)
	if e2.Comm != "sshd" {
		t.Errorf("second Resolve: Comm = %q, want sshd (fallback result should have been cached)", e2.Comm)
	}
}

// TestResolveUnknownPIDLeavesEnrichmentEmpty ensures a pid never observed
// and absent from procfs yields no fabricated attribution, per event.Event's
// "empty means not known, never guessed" rule.
func TestResolveUnknownPIDLeavesEnrichmentEmpty(t *testing.T) {
	src := NewFakeSource()
	c := New(10, 2, src)

	e := &event.Event{PID: 9999, UID: 4242}
	c.Resolve(e)

	if e.Comm != "" || e.Cgroup != "" || e.Unit != "" || e.Container != "" || e.User != "" {
		t.Errorf("expected empty enrichment for unknown pid, got %+v", e.Enrichment)
	}
}

// TestLRUEvictsLeastRecentlyUsed checks capacity-driven eviction picks the
// entry least recently touched by either Observe or Resolve, not the oldest
// by insertion order or by process exit time — eviction here is purely an
// LRU policy over capacity, independent of whether the underlying process
// is alive.
func TestLRUEvictsLeastRecentlyUsed(t *testing.T) {
	src := NewFakeSource()
	c := New(2, 0, src)

	c.Observe(event.Event{Class: event.ClassExec, PID: 1, Enrichment: event.Enrichment{Comm: "one"}})
	c.Observe(event.Event{Class: event.ClassExec, PID: 2, Enrichment: event.Enrichment{Comm: "two"}})

	// Touch pid 1 again so pid 2 becomes the least-recently-used.
	e1 := &event.Event{PID: 1}
	c.Resolve(e1)

	// Inserting pid 3 must evict pid 2, not pid 1.
	c.Observe(event.Event{Class: event.ClassExec, PID: 3, Enrichment: event.Enrichment{Comm: "three"}})

	if c.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", c.Len())
	}

	e1b := &event.Event{PID: 1}
	c.Resolve(e1b)
	if e1b.Comm != "one" {
		t.Errorf("pid 1 should have survived (recently touched); Comm = %q", e1b.Comm)
	}

	e2 := &event.Event{PID: 2}
	c.Resolve(e2)
	if e2.Comm != "" {
		t.Errorf("pid 2 should have been evicted; Comm = %q", e2.Comm)
	}

	e3 := &event.Event{PID: 3}
	c.Resolve(e3)
	if e3.Comm != "three" {
		t.Errorf("pid 3 should be present; Comm = %q", e3.Comm)
	}
}

// TestAncestorsDepthLimited verifies ancestor chains stop at maxAncestors
// hops, nearest-first, and cope with a chain shorter than the limit.
func TestAncestorsDepthLimited(t *testing.T) {
	src := NewFakeSource()
	// Chain: 4 (target) -> 3 -> 2 -> 1 (init-like, ppid 0)
	src.StatusByPID[3] = FakeStatus{Comm: "shell", PPid: 2}
	src.StatusByPID[2] = FakeStatus{Comm: "systemd-user", PPid: 1}
	src.StatusByPID[1] = FakeStatus{Comm: "systemd", PPid: 0}

	c := New(10, 2, src) // depth limit 2
	c.Observe(event.Event{
		Class:      event.ClassExec,
		PID:        4,
		Enrichment: event.Enrichment{Comm: "leaf", Ppid: 3},
	})

	e := &event.Event{PID: 4}
	c.Resolve(e)

	want := []string{"shell", "systemd-user"}
	if len(e.Ancestors) != len(want) {
		t.Fatalf("Ancestors = %v, want %v", e.Ancestors, want)
	}
	for i := range want {
		if e.Ancestors[i] != want[i] {
			t.Errorf("Ancestors[%d] = %q, want %q", i, e.Ancestors[i], want[i])
		}
	}
}

// TestAncestorsZeroDisabled verifies maxAncestors=0 disables ancestor chains
// entirely rather than producing an empty-but-present slice inconsistently.
func TestAncestorsZeroDisabled(t *testing.T) {
	src := NewFakeSource()
	src.StatusByPID[1] = FakeStatus{Comm: "init", PPid: 0}
	c := New(10, 0, src)
	c.Observe(event.Event{Class: event.ClassExec, PID: 2, Enrichment: event.Enrichment{Comm: "x", Ppid: 1}})

	e := &event.Event{PID: 2}
	c.Resolve(e)
	if len(e.Ancestors) != 0 {
		t.Errorf("Ancestors = %v, want none", e.Ancestors)
	}
}

// TestAncestorChainCycleDoesNotHang guards against a corrupt/cyclic ppid
// chain (which should never happen from a real process tree, but procfs is
// the one input Wake does not fully control) looping forever.
func TestAncestorChainCycleDoesNotHang(t *testing.T) {
	src := NewFakeSource()
	src.StatusByPID[1] = FakeStatus{Comm: "a", PPid: 2}
	src.StatusByPID[2] = FakeStatus{Comm: "b", PPid: 1} // cycle: 1 <-> 2

	c := New(10, 50, src)
	c.Observe(event.Event{Class: event.ClassExec, PID: 3, Enrichment: event.Enrichment{Comm: "leaf", Ppid: 1}})

	done := make(chan struct{})
	go func() {
		e := &event.Event{PID: 3}
		c.Resolve(e)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Resolve did not return: ancestor cycle likely caused an infinite loop")
	}
}

func TestNewClampsInvalidCapacity(t *testing.T) {
	src := NewFakeSource()
	c := New(0, -1, src)
	c.Observe(event.Event{Class: event.ClassExec, PID: 1, Enrichment: event.Enrichment{Comm: "x"}})
	if c.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 (capacity should clamp to at least 1)", c.Len())
	}
}

// TestUserAlwaysResolvedFromEventUID checks that User resolution does not
// depend on the pid cache at all: it must work even for a pid the cache has
// never heard of, since the uid rides on every event's own header.
func TestUserAlwaysResolvedFromEventUID(t *testing.T) {
	src := NewFakeSource()
	src.Users[42] = "svc-account"
	c := New(10, 0, src)

	e := &event.Event{PID: 123456, UID: 42}
	c.Resolve(e)
	if e.User != "svc-account" {
		t.Errorf("User = %q, want svc-account", e.User)
	}
}

// TestConcurrentObserveAndResolve exercises Observe/Resolve from many
// goroutines under -race.
func TestConcurrentObserveAndResolve(t *testing.T) {
	src := NewFakeSource()
	for i := int32(0); i < 50; i++ {
		src.StatusByPID[i] = FakeStatus{Comm: "p", PPid: 1}
		src.CgroupByPID[i] = "/system.slice/x.service"
	}
	c := New(20, 2, src)

	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			for i := 0; i < 200; i++ {
				pid := int32((g*200 + i) % 50)
				if i%2 == 0 {
					c.Observe(event.Event{Class: event.ClassExec, PID: pid, Enrichment: event.Enrichment{Comm: "p", Ppid: 1}})
				} else {
					e := &event.Event{PID: pid}
					c.Resolve(e)
				}
			}
			done <- struct{}{}
		}(g)
	}
	for g := 0; g < 8; g++ {
		<-done
	}
}
