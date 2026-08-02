package ctl

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// fakeHandler stands in for the daemon, so that the protocol can be tested
// without a kernel, a ring, or a snapshot directory.
type fakeHandler struct {
	mu        sync.Mutex
	triggers  []string
	events    chan event.Event
	cancelled bool
}

func newFakeHandler() *fakeHandler {
	return &fakeHandler{events: make(chan event.Event, 8)}
}

func (h *fakeHandler) Status() Status {
	return Status{Version: "test", PID: 1234, Events: 7, MaxEvents: 100,
		Drops: (&event.Drops{}).Report()}
}

func (h *fakeHandler) Trigger(reason string) TriggerResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.triggers = append(h.triggers, reason)
	return TriggerResult{Accepted: true, Path: "/var/lib/wake/snapshots/x", Events: 42}
}

func (h *fakeHandler) Subscribe([]string, string) (<-chan event.Event, func()) {
	return h.events, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.cancelled = true
	}
}

func startServer(t *testing.T) (string, *fakeHandler) {
	t.Helper()
	h := newFakeHandler()
	path := filepath.Join(t.TempDir(), "wake.sock")

	srv, err := Listen(path, h, discardLogger())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-done
	})
	return path, h
}

func TestStatusRoundTrip(t *testing.T) {
	t.Parallel()
	path, _ := startServer(t)

	conn, dec, err := Dial(path, Request{Command: CmdStatus})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var resp Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status == nil || resp.Status.Events != 7 {
		t.Fatalf("status = %+v", resp.Status)
	}
	if resp.Status.Drops == nil {
		t.Error("status must always carry the drop report, even when it is all zeroes")
	}
}

func TestTriggerCarriesTheOperatorsReason(t *testing.T) {
	t.Parallel()
	path, h := startServer(t)

	conn, dec, err := Dial(path, Request{Command: CmdTrigger, Reason: "iserver stalled"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var resp Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Result == nil || !resp.Result.Accepted {
		t.Fatalf("result = %+v", resp.Result)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.triggers) != 1 || h.triggers[0] != "iserver stalled" {
		t.Errorf("triggers = %q", h.triggers)
	}
}

func TestWatchStreamsEventsAndCancelsOnDisconnect(t *testing.T) {
	t.Parallel()
	path, h := startServer(t)

	conn, dec, err := Dial(path, Request{Command: CmdWatch})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	ev := event.Event{Class: event.ClassExec, PID: 99, Timestamp: time.Now().UTC()}
	ev.Comm = "smtpd"
	h.events <- ev

	var resp Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Event == nil || resp.Event.Comm != "smtpd" {
		t.Fatalf("event = %+v", resp.Event)
	}

	_ = conn.Close()
	close(h.events)

	// The subscription must be released, or every `wake watch` a support
	// engineer ever ran would leak a fan-out channel.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		done := h.cancelled
		h.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("watch subscription was never cancelled after the client disconnected")
}

func TestUnknownCommandIsRejectedClearly(t *testing.T) {
	t.Parallel()
	path, _ := startServer(t)

	conn, dec, err := Dial(path, Request{Command: "telepathy"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var resp Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == "" {
		t.Error("an unknown command must be reported, not silently ignored")
	}
}

func TestMalformedRequestDoesNotKillTheServer(t *testing.T) {
	t.Parallel()
	path, _ := startServer(t)

	conn, err := dialRaw(path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("this is not json\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == "" {
		t.Error("a malformed request should be answered with an error")
	}
	_ = conn.Close()

	// The server must still be serving.
	conn2, dec, err := Dial(path, Request{Command: CmdStatus})
	if err != nil {
		t.Fatalf("server died after a malformed request: %v", err)
	}
	defer func() { _ = conn2.Close() }()
	var ok Response
	if err := dec.Decode(&ok); err != nil || ok.Status == nil {
		t.Errorf("server no longer answers status: %v / %+v", err, ok.Status)
	}
}

// TestSocketIsRootOnly guards the privacy line: being able to ask for a
// snapshot means being able to read other people's command lines.
func TestSocketIsRootOnly(t *testing.T) {
	t.Parallel()
	path, _ := startServer(t)

	fi, err := statFile(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %o, want 600", perm)
	}
}

// Small helpers, kept at the bottom so the tests above read as behaviour.

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func dialRaw(path string) (net.Conn, error) { return net.Dial("unix", path) }

func statFile(path string) (os.FileInfo, error) { return os.Stat(path) }
