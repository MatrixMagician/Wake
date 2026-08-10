// Package enrich implements Wake's enrichment cache: the size-capped,
// continuously-maintained record of pid -> {comm, ancestry, cgroup, systemd
// unit, container ID, user} that lets a snapshot attribute an event to a
// process even when that process exited long before the trigger fired
// (SPEC.md §2 goal 6, CONTEXT.md "Enrichment cache").
//
// The cache is the second (and last) steady-state consumer of memory the
// daemon carries deliberately, alongside the ring; both are size-capped so
// neither can grow without bound (CLAUDE.md, "the ring is the only
// steady-state memory consumer" — the enrichment cache is its capped
// sibling, not an exception to that rule).
package enrich

import (
	"container/list"
	"sync"

	"github.com/MatrixMagician/wake/internal/event"
)

// ProcSource abstracts the two things the cache cannot know from wire events
// alone: a live process's ancestry/identity via /proc/<pid>/status, and its
// cgroup membership via /proc/<pid>/cgroup. It exists so unit tests never
// touch a real /proc: ProcfsSource is the production implementation and
// FakeSource (procfs.go) is an in-memory double.
//
// All three methods report ok=false for anything unknown or unreadable
// (pid exited, uid absent from the user database, and so on) rather than
// returning a zero value that could be mistaken for real data — the cache's
// job is to admit ignorance, never to guess (see event.Enrichment's doc
// comment on the same point).
type ProcSource interface {
	// Status returns a live process's comm and parent pid, read from
	// /proc/<pid>/status. The uid is deliberately not here: it travels on
	// every event's own header (event.Event.UID) regardless of class, so it
	// is always available first-hand rather than through a pid-keyed lookup
	// that can only fail once the process is gone.
	Status(pid int32) (comm string, ppid int32, ok bool)
	// Cgroup returns a live process's cgroup path, read from
	// /proc/<pid>/cgroup (the unified-hierarchy line where present).
	Cgroup(pid int32) (path string, ok bool)
	// User resolves a numeric uid to a username via the system user
	// database (e.g. /etc/passwd).
	User(uid uint32) (name string, ok bool)
}

// entry is one cached process's attribution. Fields are immutable once
// built: Observe always constructs a fresh entry rather than mutating one in
// place, so a lookup racing a rebuild never sees a half-written record.
type entry struct {
	pid       int32
	comm      string
	ppid      int32
	ancestors []string
	cgroup    string
	unit      string
	container string
}

// Cache is a concurrency-safe, size-capped LRU from pid to entry.
//
// Capacity bounds entry *count*, not bytes: unlike the ring (which trades
// off against a hard memory budget because it holds arbitrarily large
// argv/path payloads), an enrichment entry is a handful of short strings, so
// a count cap keeps the accounting simple without materially risking the
// memory budget SPEC.md §3 sets for the whole daemon.
//
// Capacity, not liveness, drives eviction: an entry for a process that
// exited stays exactly as attributable as one for a live process until
// something newer pushes it out. That is the entire point of the cache
// (SPEC.md §2 goal 6, "already exited ... still attributable").
type Cache struct {
	mu           sync.Mutex
	capacity     int
	maxAncestors int
	source       ProcSource
	ll           *list.List // front = most recently used
	items        map[int32]*list.Element
}

// New constructs a Cache holding at most capacity entries, walking at most
// maxAncestors parent-process hops when building an ancestor chain (0
// disables ancestor chains entirely). source supplies procfs/user-database
// lookups; pass a *ProcfsSource in production and a *FakeSource in tests.
func New(capacity, maxAncestors int, source ProcSource) *Cache {
	if capacity < 1 {
		capacity = 1
	}
	if maxAncestors < 0 {
		maxAncestors = 0
	}
	return &Cache{
		capacity:     capacity,
		maxAncestors: maxAncestors,
		source:       source,
		ll:           list.New(),
		items:        make(map[int32]*list.Element, capacity),
	}
}

// Observe feeds one decoded event into the cache. Only exec and exit events
// change the cache's contents — they are Wake's two process-lifecycle
// signals (CONTEXT.md: "Event" — everything else is activity, not identity,
// and Resolve's procfs fallback already covers pids Observe never saw.
//
// Observe never blocks the ring: callers are expected to invoke it from the
// same decode-and-fan-out step that feeds the ring, off any latency-critical
// path, and it does its own (bounded) procfs I/O rather than deferring work
// to Resolve, because at exec/exit time the process is still guaranteed (or
// very likely, for exit) to be alive — the one moment its cgroup path can
// still be read at all.
func (c *Cache) Observe(e event.Event) {
	switch e.Class {
	case event.ClassExec:
		c.observeExec(e)
	case event.ClassExit:
		c.observeExit(e)
	}
}

// observeExec builds a fresh, authoritative entry at the one moment Wake can
// be certain the process exists: the exec event fires from inside the
// kernel's own exec path. e.Comm/e.Ppid are used when the decoder already
// populated them from the wire header; the procfs source is consulted only
// to fill genuine gaps (a defensive hedge against decode changes, not the
// expected path) and, always, for the cgroup lookup, which the wire format
// carries only as an opaque cgroup ID, not a path (see bpf/wake_event.h).
func (c *Cache) observeExec(e event.Event) {
	comm, ppid := e.Comm, e.Ppid
	if comm == "" || ppid == 0 {
		if sComm, sPpid, ok := c.source.Status(e.PID); ok {
			if comm == "" {
				comm = sComm
			}
			if ppid == 0 {
				ppid = sPpid
			}
		}
	}
	cgroupPath, _ := c.source.Cgroup(e.PID)
	unit, container := ParseCgroup(cgroupPath)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(&entry{
		pid:       e.PID,
		comm:      comm,
		ppid:      ppid,
		ancestors: c.buildAncestorsLocked(ppid),
		cgroup:    cgroupPath,
		unit:      unit,
		container: container,
	})
}

// observeExit is the second lifecycle signal. In the common case the exec
// event already built the entry, so exit only needs to keep it warm — it is
// very likely the pid a trigger is about to snapshot, since triggers
// SPEC.md's watched-process rule fires on exactly this event. In the
// uncommon case (the process predates Wake, or its exec record was itself
// dropped) this is the last chance to capture anything at all, on a
// best-effort basis: /proc/<pid> may already be gone for a reaped process by
// the time this runs in userspace, and that is not an error, just the
// reason the fallback in Resolve exists too.
func (c *Cache) observeExit(e event.Event) {
	c.mu.Lock()
	if el, ok := c.items[e.PID]; ok {
		c.ll.MoveToFront(el)
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	comm, ppid := e.Comm, int32(0)
	if sComm, sPpid, ok := c.source.Status(e.PID); ok {
		if comm == "" {
			comm = sComm
		}
		ppid = sPpid
	}
	cgroupPath, cgOK := c.source.Cgroup(e.PID)
	if comm == "" && !cgOK {
		return // nothing recoverable; do not cache an empty husk that would
		// block a later, possibly more successful, fallback lookup.
	}
	unit, container := ParseCgroup(cgroupPath)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(&entry{
		pid:       e.PID,
		comm:      comm,
		ppid:      ppid,
		ancestors: c.buildAncestorsLocked(ppid),
		cgroup:    cgroupPath,
		unit:      unit,
		container: container,
	})
}

// Resolve fills e's embedded event.Enrichment in place, at snapshot time
// (SPEC.md §2 goal 6). It first consults the cache; on a miss it falls back
// to a fresh procfs read for pids Observe never saw — a live process present
// when the daemon started, for instance — and, on success, caches the
// result so a busy snapshot resolving the same pid repeatedly only pays for
// procfs once.
//
// A total miss (process gone, never observed, uid unknown) leaves the
// corresponding Enrichment fields at their zero value, which event.Event's
// doc comment defines as "not known" and serialises as absent — Resolve
// never fabricates an attribution it cannot support.
func (c *Cache) Resolve(e *event.Event) {
	c.mu.Lock()
	ent, ok := c.getLocked(e.PID)
	c.mu.Unlock()

	if !ok {
		if fetched, fOK := c.fallback(e.PID); fOK {
			ent, ok = fetched, true
			c.mu.Lock()
			c.putLocked(ent)
			c.mu.Unlock()
		}
	}

	if ok {
		e.Comm = ent.comm
		e.Ppid = ent.ppid
		e.Ancestors = ent.ancestors
		e.Cgroup = ent.cgroup
		e.Unit = ent.unit
		e.Container = ent.container
	}

	// Username resolution needs no per-pid cache: the uid travels on every
	// event's own header (event.Event.UID) regardless of class, so it is
	// always available first-hand rather than through the pid-keyed cache.
	if name, uOK := c.source.User(e.UID); uOK {
		e.User = name
	}
}

// fallback rebuilds an entry from procfs for a pid Observe never recorded.
// It is best-effort in both halves independently: a process can still have a
// readable cgroup file after its status has become unreadable, or vice
// versa, so partial success is still worth caching rather than discarded.
func (c *Cache) fallback(pid int32) (*entry, bool) {
	comm, ppid, statusOK := c.source.Status(pid)
	cgroupPath, cgOK := c.source.Cgroup(pid)
	if !statusOK && !cgOK {
		return nil, false
	}
	unit, container := ParseCgroup(cgroupPath)

	c.mu.Lock()
	ancestors := c.buildAncestorsLocked(ppid)
	c.mu.Unlock()

	return &entry{
		pid:       pid,
		comm:      comm,
		ppid:      ppid,
		ancestors: ancestors,
		cgroup:    cgroupPath,
		unit:      unit,
		container: container,
	}, true
}

// buildAncestorsLocked walks the parent-pid chain starting at ppid, nearest
// first, up to c.maxAncestors hops. It must be called with c.mu held: it
// reads c.items directly (to prefer already-cached comms, which is both
// cheaper and more likely accurate than a fresh procfs read for a pid that
// is itself likely long dead by the time a deep ancestor chain is walked)
// and falls back to the procfs source only for pids the cache has not seen.
//
// A visited-set guards against a corrupt/cyclic ppid chain turning into an
// infinite loop; this should never happen from a real process tree, but a
// flight recorder must not hang on bad input from the one source (procfs)
// it cannot fully control.
func (c *Cache) buildAncestorsLocked(ppid int32) []string {
	if c.maxAncestors <= 0 || ppid <= 0 {
		return nil
	}
	var out []string
	visited := make(map[int32]bool, c.maxAncestors)
	pid := ppid
	for depth := 0; depth < c.maxAncestors; depth++ {
		if pid <= 0 || visited[pid] {
			break
		}
		visited[pid] = true

		var comm string
		var next int32
		if el, ok := c.items[pid]; ok {
			en := el.Value.(*entry)
			comm, next = en.comm, en.ppid
		} else if sComm, sPpid, ok := c.source.Status(pid); ok {
			comm, next = sComm, sPpid
		} else {
			break
		}
		if comm == "" {
			break
		}
		out = append(out, comm)
		pid = next
	}
	return out
}

// getLocked looks up pid and, on a hit, marks it most-recently-used. Callers
// must hold c.mu.
func (c *Cache) getLocked(pid int32) (*entry, bool) {
	el, ok := c.items[pid]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*entry), true
}

// putLocked inserts or replaces ent, marks it most-recently-used, and evicts
// the least-recently-used entry if capacity is now exceeded. Callers must
// hold c.mu.
func (c *Cache) putLocked(ent *entry) {
	if el, ok := c.items[ent.pid]; ok {
		el.Value = ent
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(ent)
	c.items[ent.pid] = el
	if c.ll.Len() > c.capacity {
		back := c.ll.Back()
		be := back.Value.(*entry)
		delete(c.items, be.pid)
		c.ll.Remove(back)
	}
}

// Len reports the number of entries currently cached. Intended for `wake
// status` and tests, not the hot path.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
