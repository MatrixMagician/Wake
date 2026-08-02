# Wake — build, test and measurement targets.
#
# BPF objects are compiled at build time with clang and embedded via bpf2go, so
# target hosts need neither clang nor kernel headers (SPEC.md §2 goal 8).

GO      ?= go
CLANG   ?= clang
BINARY  := wake
PKG     := github.com/MatrixMagician/wake
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION)

.PHONY: all build generate test integration smoke lint fmt perf clean tools

all: build

## bpf/vmlinux.h: CO-RE type definitions dumped from the build host's BTF.
## Generated rather than committed: it is 5 MiB of derived data, and CO-RE
## means the build host's types need not match the target's.
bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

## generate: compile the BPF C sources and produce the Go bindings.
generate: bpf/vmlinux.h
	$(GO) generate ./...

## build: static binary with the BPF objects embedded.
build: generate
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/wake

## test: unprivileged unit tests. These must never require a kernel or root.
test:
	$(GO) test -race ./...

## integration: kernel-dependent tests. Requires root and a live BTF kernel.
## Test binaries are compiled as the invoking user and only *run* under sudo,
## so that root need not have Go on its PATH.
INTEGRATION_PKGS := ./internal/loader ./internal/trigger

integration: generate
	@set -e; for pkg in $(INTEGRATION_PKGS); do \
		echo "==> $$pkg"; \
		$(GO) test -tags integration -c -o /tmp/wake-int.test $$pkg; \
		sudo /tmp/wake-int.test -test.v -test.count=1; \
	done

## lint: vet plus golangci-lint when available.
lint:
	$(GO) vet ./...
	@command -v golangci-lint 2>/dev/null || command -v $$HOME/go/bin/golangci-lint >/dev/null 2>&1 && golangci-lint run || \
		echo "golangci-lint not installed; skipping (make tools)"

fmt:
	$(GO) fmt ./...

## perf: run the in-repo load generator against a running daemon and record the
## overhead measurement in docs/perf.md. Enforces the SPEC.md §3 budget.
perf: build
	sudo ./testdata/loadgen/measure.sh

tools:
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

clean:
	rm -f $(BINARY)
	rm -f internal/loader/bpf_*.o internal/loader/bpf_*.go

## smoke: end-to-end check against a live kernel. Requires root.
smoke: build
	sudo ./testdata/smoke.sh
