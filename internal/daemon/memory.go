package daemon

import (
	"log/slog"
	"runtime/debug"
)

// applyMemoryLimit sets the Go runtime's soft memory limit from the ring's
// configured budget.
//
// Without this, the runtime's default heap growth target (GOGC=100, i.e. grow
// until the heap is twice the live set) means a 64 MiB ring settles at roughly
// 135 MiB RSS. The operator configured a budget; a recorder that quietly uses
// twice it is misreporting its own cost, and on a box that is already running
// out of memory — which is precisely when Wake matters — that overshoot is
// exactly the wrong behaviour.
//
// The limit is the ring budget plus headroom for the enrichment cache, the
// decode path, and the runtime itself. It is a *soft* limit: the GC works
// harder as it is approached rather than failing allocations, so the worst
// case is a little more CPU during a burst, which is the right trade for a
// tool whose CPU budget is measured at 0.13% of the 1% allowed.
//
// An explicit GOMEMLIMIT in the environment always wins: an operator who has
// tuned this deliberately should not be overridden.
func applyMemoryLimit(ringBudgetBytes int64, log *slog.Logger) {
	if ringBudgetBytes <= 0 {
		return
	}
	// If GOMEMLIMIT was set in the environment, the runtime has already
	// applied it and it is not math.MaxInt64.
	if current := debug.SetMemoryLimit(-1); current != defaultNoMemoryLimit {
		log.Debug("respecting GOMEMLIMIT from the environment", "limit", current)
		return
	}

	limit := ringBudgetBytes + runtimeHeadroomBytes
	debug.SetMemoryLimit(limit)
	log.Debug("memory limit set from the ring budget",
		"ring_budget", ringBudgetBytes, "limit", limit)
}

const (
	// defaultNoMemoryLimit is what the runtime reports when no limit is set.
	defaultNoMemoryLimit int64 = 1<<63 - 1

	// runtimeHeadroomBytes covers the enrichment cache, in-flight decoding,
	// the zstd encoder used during a snapshot, and the runtime's own
	// allocations. Measured empirically against the load generator: 32 MiB
	// leaves the 10k events/s case comfortably inside the SPEC's 128 MiB RSS
	// budget with a 64 MiB ring.
	runtimeHeadroomBytes int64 = 32 << 20
)
