// Package loader owns every interaction with the kernel: compiling-in the BPF
// objects, loading them, attaching the tracepoints, pushing filter
// configuration into maps, and reading the kernel-side drop counters.
//
// Nothing else in Wake imports cilium/ebpf. That boundary is what lets the
// rest of the daemon be unit-tested without a kernel: the recorder consumes a
// Source, and the fake Source in decode's tests satisfies it just as well as
// this one does.
package loader

// The Go structs mirroring the BPF records live in internal/decode, written by
// hand and pinned to the C sizes by a test, rather than generated here: the
// decoder must handle records it does *not* recognise, which a generated
// struct cannot express.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package loader -cc clang -target bpfel -output-dir . wake ../../bpf/wake.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Wno-missing-declarations
