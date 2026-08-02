// Package daemon assembles Wake's components into a running recorder.
//
// This is the only place where the concrete implementations meet: config
// becomes loader options and trigger rules, the loader becomes a Source, the
// recorder wires the ring and enrichment cache together, and the control
// socket exposes it all. Keeping that assembly in one package is what lets
// every other package be tested against fakes.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/MatrixMagician/wake/internal/config"
	"github.com/MatrixMagician/wake/internal/ctl"
	"github.com/MatrixMagician/wake/internal/decode"
	"github.com/MatrixMagician/wake/internal/enrich"
	"github.com/MatrixMagician/wake/internal/event"
	"github.com/MatrixMagician/wake/internal/loader"
	"github.com/MatrixMagician/wake/internal/recorder"
	"github.com/MatrixMagician/wake/internal/redact"
	"github.com/MatrixMagician/wake/internal/ring"
	"github.com/MatrixMagician/wake/internal/snapshot"
	"github.com/MatrixMagician/wake/internal/trigger"
	"github.com/MatrixMagician/wake/internal/version"
)

// Daemon is a running Wake.
type Daemon struct {
	cfg      *config.Config
	log      *slog.Logger
	drops    *event.Drops
	ring     *ring.Ring
	enricher *enrich.Cache
	engine   *trigger.Engine
	writer   *snapshot.Writer
	rec      *recorder.Recorder
	srv      *ctl.Server
	src      loader.Source

	startedAt time.Time

	mu           sync.Mutex
	snapshots    int
	snapshotSize int64
	lastSnapshot *time.Time
}

// New builds a daemon from configuration. It loads nothing into the kernel
// yet: Run does that, so that a configuration error is reported before any
// kernel resource is taken.
func New(cfg *config.Config, socketPath string, log *slog.Logger) (*Daemon, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	drops := &event.Drops{}
	rg, err := ring.New(cfg.Ring.Window, cfg.Ring.MaxEvents, cfg.Ring.MemoryBudgetBytes, drops)
	if err != nil {
		return nil, fmt.Errorf("building the ring: %w", err)
	}

	rules, err := triggerRules(cfg)
	if err != nil {
		return nil, err
	}
	engine, err := trigger.NewEngine(rules, nil)
	if err != nil {
		return nil, fmt.Errorf("building the trigger engine: %w", err)
	}

	d := &Daemon{
		cfg:      cfg,
		log:      log,
		drops:    drops,
		ring:     rg,
		enricher: enrich.New(enrichCapacity, maxAncestors, enrich.NewProcfsSource()),
		engine:   engine,
		writer: snapshot.NewWriter(snapshot.WriterConfig{
			Root: cfg.Snapshot.Dir,
		}),
		startedAt: time.Now(),
	}

	srv, err := ctl.Listen(socketPath, d, log)
	if err != nil {
		return nil, err
	}
	d.srv = srv
	return d, nil
}

const (
	// enrichCapacity bounds the LRU. 16k entries covers a busy host's process
	// churn for far longer than any ring window, at a few megabytes.
	enrichCapacity = 16384
	// maxAncestors bounds the ppid chain. Beyond a handful of generations the
	// chain stops being evidence and starts being init.
	maxAncestors = 8
)

// Run loads the BPF programs and records until the context is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	opts, err := loaderOptions(d.cfg)
	if err != nil {
		return err
	}

	src, err := loader.Load(opts, d.log)
	if err != nil {
		return fmt.Errorf("loading the BPF programs (run `wake doctor` for a diagnosis): %w", err)
	}
	d.src = src
	defer func() { _ = src.Close() }()

	boot, err := loader.BootTime()
	if err != nil {
		return err
	}

	d.rec = recorder.New(recorder.Options{
		Source:   src,
		Decoder:  decode.New(decode.BootClock{Boot: boot}),
		Ring:     d.ring,
		Enricher: d.enricher,
		Redactor: d.redactor(),
		Triggers: d.engine,
		Drops:    d.drops,
		Logger:   d.log,
	})

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		if err := d.rec.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			d.log.Error("recorder stopped", "err", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := d.srv.Serve(ctx); err != nil {
			d.log.Error("control socket stopped", "err", err)
		}
	}()

	go func() {
		defer wg.Done()
		d.watchTriggers(ctx)
	}()

	if d.cfg.Triggers.UnitFailed.Enabled {
		w, err := trigger.NewUnitWatcher(d.log)
		if err != nil {
			// Not fatal: a host without systemd can still record everything
			// else, and refusing to start would be a worse answer.
			d.log.Warn("unit-failure triggers unavailable", "err", err)
		} else {
			defer func() { _ = w.Close() }()
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.Run(ctx, d.engine)
			}()
		}
	}

	notifyReady(d.log)
	d.log.Info("wake recording",
		"classes", enabledClasses(d.cfg),
		"ring_window", d.cfg.Ring.Window,
		"snapshot_dir", d.cfg.Snapshot.Dir)

	<-ctx.Done()

	notifyStopping(d.log)
	if d.cfg.Snapshot.OnShutdown {
		d.log.Info("taking a snapshot on shutdown, as configured")
		d.takeSnapshot(trigger.Firing{
			Rule: "shutdown", Type: trigger.TypeManual,
			At: time.Now(), Reason: "daemon shutting down",
		})
	}

	_ = d.srv.Close()
	wg.Wait()
	return nil
}

// watchTriggers turns firings into snapshots. It runs on its own goroutine so
// that writing a snapshot never blocks the recorder: the ring was already
// frozen when the firing was emitted, so recording continues throughout.
func (d *Daemon) watchTriggers(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-d.engine.Firings():
			if !ok {
				return
			}
			d.takeSnapshot(f)
		}
	}
}

func (d *Daemon) takeSnapshot(f trigger.Firing) {
	events, drops := d.rec.Freeze()

	// Enrichment happens at snapshot time for anything the recorder could not
	// resolve when the event arrived, which is how a process that exited
	// thirty seconds ago is still attributable.
	for i := range events {
		d.enricher.Resolve(&events[i])
	}

	info := snapshot.TriggerInfo{
		Type:    string(f.Type),
		Reason:  f.Reason,
		Rule:    f.Rule,
		Unit:    f.Unit,
		FiredAt: f.At,
	}
	if f.PID != 0 {
		pid := f.PID
		info.PID = &pid
	}

	res, err := d.writer.Write(snapshot.Input{
		Events:     events,
		Drops:      drops,
		Trigger:    info,
		ConfigHash: d.cfg.Hash(),
	})
	if err != nil {
		d.log.Error("snapshot failed", "rule", f.Rule, "err", err)
		return
	}
	d.log.Info("snapshot written",
		"path", res.Path, "events", len(events), "rule", f.Rule, "reason", f.Reason)

	now := time.Now()
	d.mu.Lock()
	d.snapshots++
	d.lastSnapshot = &now
	d.mu.Unlock()

	if _, err := d.writer.Prune(snapshot.RetentionSettings{
		MaxCount:      d.cfg.Snapshot.RetentionCount,
		MaxTotalBytes: d.cfg.Snapshot.RetentionBytes,
	}); err != nil {
		d.log.Warn("retention pruning failed", "err", err)
	}
}

// Trigger takes a manual snapshot. Used by SIGUSR1 and the control socket.
func (d *Daemon) Trigger(reason string) ctl.TriggerResult {
	if !d.cfg.Triggers.Manual.Enabled {
		return ctl.TriggerResult{Accepted: false,
			Message: "manual triggers are disabled in the configuration"}
	}
	d.engine.Manual(reason)
	return ctl.TriggerResult{Accepted: true,
		Message: "snapshot requested; see the journal for the path"}
}

// Subscribe implements ctl.Handler.
func (d *Daemon) Subscribe(classes []string, unit string) (<-chan event.Event, func()) {
	if d.rec == nil {
		ch := make(chan event.Event)
		close(ch)
		return ch, func() {}
	}
	return d.rec.Subscribe(classes, unit)
}

// Status implements ctl.Handler.
func (d *Daemon) Status() ctl.Status {
	d.mu.Lock()
	snaps, size, last := d.snapshots, d.snapshotSize, d.lastSnapshot
	d.mu.Unlock()

	st := ctl.Status{
		Version:       version.Version,
		PID:           os.Getpid(),
		StartedAt:     d.startedAt,
		Uptime:        time.Since(d.startedAt),
		Events:        d.ring.Len(),
		MaxEvents:     d.cfg.Ring.MaxEvents,
		Bytes:         int(d.ring.Bytes()),
		MaxBytes:      int(d.cfg.Ring.MemoryBudgetBytes),
		Window:        d.cfg.Ring.Window,
		Drops:         d.drops.Report(),
		Classes:       enabledClasses(d.cfg),
		Snapshots:     snaps,
		SnapshotBytes: size,
		LastSnapshot:  last,
		ConfigHash:    d.cfg.Hash(),
	}

	suppressed := d.engine.Suppressed()
	rules, err := triggerRules(d.cfg)
	if err == nil {
		for _, r := range rules {
			st.Rules = append(st.Rules, ctl.RuleStatus{
				Name:       r.Name,
				Type:       string(r.Type),
				Cooldown:   r.Cooldown.String(),
				Suppressed: suppressed[r.Name],
			})
		}
	}
	return st
}

func (d *Daemon) redactor() recorder.Redactor {
	r, err := redact.New(d.cfg.Redaction)
	if err != nil {
		// Validate already checked the patterns, so this cannot normally
		// happen; refusing to redact would be a privacy failure, so fail loud.
		d.log.Error("redaction rules could not be compiled", "err", err)
		return nil
	}
	return r
}

func enabledClasses(cfg *config.Config) []string {
	var out []string
	for _, c := range event.Classes {
		if c == event.ClassGeneric {
			continue
		}
		if cfg.Classes[string(c)] {
			out = append(out, string(c))
		}
	}
	return out
}
