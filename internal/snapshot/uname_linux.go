package snapshot

import "syscall"

// osUname calls the real uname(2) syscall. Wake is Linux-only (SPEC.md §2
// Non-Goals: "No Windows/macOS"), so no build tags or cross-platform
// abstraction is needed here.
func osUname() (Uname, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return Uname{}, err
	}
	return Uname{
		Sysname:  int8SliceToString(u.Sysname[:]),
		Nodename: int8SliceToString(u.Nodename[:]),
		Release:  int8SliceToString(u.Release[:]),
		Version:  int8SliceToString(u.Version[:]),
		Machine:  int8SliceToString(u.Machine[:]),
	}, nil
}

// int8SliceToString converts a NUL-terminated []int8 (as syscall.Utsname's
// fields are typed on linux/amd64 and most other Linux architectures) to a
// Go string, stopping at the first NUL.
func int8SliceToString(s []int8) string {
	b := make([]byte, 0, len(s))
	for _, c := range s {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
