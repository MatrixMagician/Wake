package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/MatrixMagician/wake/internal/event"
)

// Handler is what the daemon supplies to serve control requests. Keeping this
// an interface is what lets the server be tested over a socketpair with no
// recorder behind it.
type Handler interface {
	// Status returns the current recorder state.
	Status() Status
	// Trigger requests a snapshot and blocks until it is written.
	Trigger(reason string) TriggerResult
	// Subscribe registers a watch stream, returning a channel of events and a
	// cancel function. The daemon drops events for a slow watcher rather than
	// slowing the recorder, counting them at event.BoundaryWatch.
	Subscribe(classes []string, unit string) (<-chan event.Event, func())
}

// Server listens on the control socket.
type Server struct {
	path string
	ln   net.Listener
	h    Handler
	log  *slog.Logger
	wg   sync.WaitGroup
}

// Listen creates the socket directory and binds. The socket is 0600 and its
// directory 0700, because being able to ask for a snapshot means being able to
// read other people's command lines.
func Listen(path string, h Handler, log *slog.Logger) (*Server, error) {
	if path == "" {
		path = SocketPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating the control socket directory: %w", err)
	}
	// A socket left behind by an unclean shutdown would otherwise make the
	// daemon unstartable, which is a poor way to treat someone whose machine
	// just crashed.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing the stale control socket: %w", err)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("restricting the control socket to root: %w", err)
	}

	return &Server{path: path, ln: ln, h: h, log: log}, nil
}

// Serve accepts connections until the context is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			// A cancelled context closed the listener from under us; that is
			// a clean shutdown, not the accept failure it looks like.
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil //nolint:nilerr // deliberate: cancellation is not an error
			}
			return fmt.Errorf("accepting a control connection: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

// Close stops listening and removes the socket.
func (s *Server) Close() error {
	err := s.ln.Close()
	_ = os.Remove(s.path)
	return err
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	dec := json.NewDecoder(bufio.NewReader(conn))
	enc := json.NewEncoder(conn)

	var req Request
	if err := dec.Decode(&req); err != nil {
		_ = enc.Encode(Response{Error: fmt.Sprintf("malformed request: %v", err)})
		return
	}

	switch req.Command {
	case CmdStatus:
		st := s.h.Status()
		_ = enc.Encode(Response{Status: &st})
	case CmdTrigger:
		res := s.h.Trigger(req.Reason)
		_ = enc.Encode(Response{Result: &res})
	case CmdWatch:
		s.watch(ctx, enc, req)
	default:
		_ = enc.Encode(Response{Error: fmt.Sprintf("unknown command %q", req.Command)})
	}
}

// watch streams events until the client goes away. It writes the same JSONL
// the snapshot contains, through the same encoder, so that live output and
// persisted output can never drift (SPEC.md §10, question 4).
func (s *Server) watch(ctx context.Context, enc *json.Encoder, req Request) {
	events, cancel := s.h.Subscribe(req.Classes, req.Unit)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := enc.Encode(Response{Event: &ev}); err != nil {
				// The client hung up, which is the normal way a watch ends.
				return
			}
		}
	}
}

// Dial connects to a running daemon, sends one request, and returns the
// connection with a decoder positioned for the reply. Callers that expect a
// stream keep reading; callers that expect one response read once.
func Dial(path string, req Request) (net.Conn, *json.Decoder, error) {
	if path == "" {
		path = SocketPath
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to the wake daemon at %s "+
			"(is it running? is this shell root?): %w", path, err)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("sending the %s request: %w", req.Command, err)
	}
	return conn, json.NewDecoder(bufio.NewReader(conn)), nil
}
