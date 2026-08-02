//go:build loadgen

// Command loadgen generates kernel events at a controlled rate, so that Wake's
// overhead budget (SPEC.md §3: < 1% CPU and < 128 MiB RSS at 10k events/s) is
// a measurement rather than a hope.
//
// It deliberately generates the *cheap* events — openat on a file that does
// not exist — because the point is to saturate the event pipeline, not the
// kernel's own work. An event Wake filters in kernel still costs a tracepoint
// hit, which is exactly what we want to price.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	rate := flag.Int("rate", 10000, "target events per second")
	dur := flag.Duration("duration", 60*time.Second, "how long to generate for")
	workers := flag.Int("workers", runtime.NumCPU(), "concurrent generators")
	flag.Parse()

	var generated atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup

	perWorker := *rate / *workers
	if perWorker < 1 {
		perWorker = 1
	}
	interval := time.Second / time.Duration(perWorker)

	for w := range *workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			t := time.NewTicker(interval)
			defer t.Stop()
			path := fmt.Sprintf("/tmp/wake-loadgen-%d-does-not-exist", id)
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					// ENOENT is the point: failing opens are the interesting
					// ones, and they cost the kernel least.
					if f, err := os.Open(path); err == nil {
						_ = f.Close()
					}
					generated.Add(1)
				}
			}
		}(w)
	}

	start := time.Now()
	progress := time.NewTicker(5 * time.Second)
	defer progress.Stop()
	deadline := time.After(*dur)

	for done := false; !done; {
		select {
		case <-deadline:
			done = true
		case <-progress.C:
			n := generated.Load()
			fmt.Printf("%.0fs: %d events, %.0f/s\n",
				time.Since(start).Seconds(), n, float64(n)/time.Since(start).Seconds())
		}
	}

	close(stop)
	wg.Wait()

	n := generated.Load()
	elapsed := time.Since(start).Seconds()
	fmt.Printf("\ngenerated %d events in %.1fs (%.0f/s sustained)\n",
		n, elapsed, float64(n)/elapsed)
}
