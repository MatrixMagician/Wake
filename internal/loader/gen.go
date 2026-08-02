// Package loader owns every interaction with the kernel: compiling-in the BPF
// objects, loading them, attaching the tracepoints, pushing filter
// configuration into maps, and reading the kernel-side drop counters.
//
// Nothing else in Wake imports cilium/ebpf. That boundary is what lets the
// rest of the daemon be unit-tested without a kernel: the recorder consumes a
// Source, and the fake Source in decode's tests satisfies it just as well as
// this one does.
package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package loader -type wake_exec -type wake_exit -type wake_signal -type wake_oom -type wake_open -type wake_connect -cc clang -target bpfel -output-dir . wake ../../bpf/wake.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86 -O2 -g -Wall
