# Wake — build, test and measurement targets.
#
# BPF objects are compiled at build time with clang and embedded via bpf2go, so
# target hosts need neither clang nor kernel headers (SPEC.md §2 goal 8).

GO      ?= go
CLANG   ?= clang

# bpftool is genuinely awkward to locate. Debian and Ubuntu ship the real
# binary under /usr/lib/linux-tools/<kernel>/, and put a wrapper on PATH that
# dispatches to the linux-tools package matching the *running* kernel -- which,
# on a cloud VM booting a vendor kernel, is frequently not installed. The
# wrapper then exits non-zero with a "you may want to install" notice, so
# bpftool looks present and is unusable. That is exactly what broke CI here.
# Prefer a PATH binary that actually runs, else fall back to a real one on disk.
BPFTOOL ?= $(shell command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1 && command -v bpftool || ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | tail -1)

BINARY  := wake
PKG     := github.com/MatrixMagician/wake
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION)

.PHONY: all build generate test integration smoke lint fmt perf fixture clean tools tools-lint

all: build

## bpf/vmlinux.h: CO-RE type definitions dumped from the build host's BTF.
## Generated rather than committed: it is 5 MiB of derived data, and CO-RE
## means the build host's types need not match the target's.
bpf/vmlinux.h:
	@test -n "$(BPFTOOL)" || { \
		echo "bpftool not found or not runnable."; \
		echo "  Debian/Ubuntu: apt install linux-tools-generic"; \
		echo "  Fedora/RHEL:   dnf install bpftool"; \
		echo "If it is installed but broken, the PATH wrapper is asking for a"; \
		echo "linux-tools package matching your running kernel; point BPFTOOL="; \
		echo "at the real binary under /usr/lib/linux-tools/ instead."; \
		exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

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

## fixture: regenerate the reference snapshot consumers test against.
##
## This is NOT the remedy for a failing schema test — see CHANGELOG.md,
## "Before you bump it". Run it after a deliberate, recorded schema change.
fixture:
	$(GO) run ./internal/snapshot/mkfixture -out testdata/fixtures
	@echo "Regenerated. If schema_version changed, add a CHANGELOG.md entry."

## lint: vet plus golangci-lint when available.
##
## golangci-lint refuses to run when the Go release it was *built with* is
## older than the go directive in go.mod, so a prebuilt binary lags this module
## and fails with a config-load error rather than a lint finding. Installing it
## with this repo's toolchain avoids that entirely.
GOLANGCI_VERSION ?= v2.12.2
GOLANGCI ?= $(shell command -v golangci-lint 2>/dev/null || ls $$HOME/go/bin/golangci-lint 2>/dev/null)

lint:
	$(GO) vet ./...
	@test -n "$(GOLANGCI)" || { echo "golangci-lint not installed; skipping (make tools)"; exit 0; }
	@test -z "$(GOLANGCI)" || $(GOLANGCI) run ./...

fmt:
	$(GO) fmt ./...

## perf: run the in-repo load generator against a running daemon and record the
## overhead measurement in docs/perf.md. Enforces the SPEC.md §3 budget.
perf: build
	sudo ./testdata/loadgen/measure.sh

## tools-lint: just the linter, for CI, which does not need bpf2go separately.
tools-lint:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

tools:
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest
	# The /v2 module path and a pinned version: v1's path still resolves and
	# silently installs a binary that cannot read a v2 .golangci.yml.
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

clean:
	rm -f $(BINARY)
	rm -f internal/loader/bpf_*.o internal/loader/bpf_*.go

## smoke: end-to-end check against a live kernel. Requires root.
smoke: build
	sudo ./testdata/smoke.sh
