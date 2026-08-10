package snapshot

import "golang.org/x/sys/unix"

// osUname calls the real uname(2) syscall. Wake is Linux-only (SPEC.md §2
// Non-Goals: "No Windows/macOS"), so no build tags or cross-platform
// abstraction is needed here.
//
// unix.Utsname is used in preference to syscall.Utsname because its fields are
// []byte rather than []int8, which means unix.ByteSliceToString handles the
// NUL-termination instead of a hand-rolled loop.
func osUname() (Uname, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return Uname{}, err
	}
	return Uname{
		Sysname:  unix.ByteSliceToString(u.Sysname[:]),
		Nodename: unix.ByteSliceToString(u.Nodename[:]),
		Release:  unix.ByteSliceToString(u.Release[:]),
		Version:  unix.ByteSliceToString(u.Version[:]),
		Machine:  unix.ByteSliceToString(u.Machine[:]),
	}, nil
}
