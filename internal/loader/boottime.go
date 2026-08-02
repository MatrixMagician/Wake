package loader

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// BootTime returns the wall-clock instant the system booted, which is what
// turns a BPF boot-time nanosecond stamp into a timestamp an operator can
// correlate with their logs.
//
// It is sampled once and reused: resampling would make two identical records
// decode to different times, and a flight recorder whose clock wanders is
// worse than one with a small fixed offset.
func BootTime() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Time{}, fmt.Errorf("reading CLOCK_BOOTTIME: %w", err)
	}
	uptime := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)
	return time.Now().Add(-uptime).UTC(), nil
}
