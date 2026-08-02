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

.PHONY: all build generate test integration lint fmt perf clean tools doctor

all: build

## generate: compile the BPF C sources and produce the Go bindings.
generate:
	$(GO) generate ./...

## build: static binary with the BPF objects embedded.
build: generate
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/wake

## test: unprivileged unit tests. These must never require a kernel or root.
test:
	$(GO) test -race ./...

## integration: kernel-dependent tests. Requires root and a live BTF kernel.
integration: generate
	sudo $(GO) test -tags integration -exec sudo -count=1 ./...

## lint: vet plus golangci-lint when available.
lint:
	$(GO) vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || \
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
