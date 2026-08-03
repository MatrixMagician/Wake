package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/MatrixMagician/wake/internal/config"
	"github.com/MatrixMagician/wake/internal/daemon"
)

func runCmd(opts *options) *cobra.Command {
	var logLevel string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the recorder (the daemon)",
		Long: "Loads the BPF programs, records into the bounded ring, and writes a\n" +
			"snapshot when a trigger fires. Writes nothing during normal operation.\n\n" +
			"Sends readiness to systemd when run under the shipped unit.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log, err := newLogger(logLevel)
			if err != nil {
				return err
			}

			cfg, err := config.Load(opts.configPath)
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			log.Info("configuration loaded", "path", opts.configPath, "hash", cfg.Hash())

			// SIGINT and SIGTERM stop the daemon; SIGUSR1 is a manual trigger
			// (SPEC.md §2 goal 4d), which is the one signal a support engineer
			// can send without a control socket.
			ctx, stop := signal.NotifyContext(context.Background(),
				syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			d, err := daemon.New(cfg, opts.socketPath, log)
			if err != nil {
				return err
			}

			usr1 := make(chan os.Signal, 1)
			signal.Notify(usr1, syscall.SIGUSR1)
			defer signal.Stop(usr1)

			// SIGHUP is explicitly ignored rather than left at its default.
			// The default action for an unhandled SIGHUP is to terminate, so
			// a flight recorder that inherits a hangup -- from a closing
			// terminal, or from an ExecReload= that assumes the daemon
			// reloads -- would silently stop recording at exactly the moment
			// it is most wanted, with systemd reporting a clean exit. Wake
			// does not support reconfiguration in place: the config hash is
			// captured per snapshot and swapping it under a live ring would
			// make that record a lie. Restart the unit to change config.
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			defer signal.Stop(hup)
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-hup:
						log.Warn("SIGHUP received and ignored; Wake does not reload in place, restart the service to apply configuration changes")
					}
				}
			}()

			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-usr1:
						log.Info("SIGUSR1 received; taking a snapshot")
						d.Trigger("SIGUSR1 received")
					}
				}
			}()

			if err := d.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			log.Info("wake stopped")
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.configPath, "config", "/etc/wake/wake.toml",
		"path to the configuration file")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "debug, info, warn or error")
	return cmd
}

func newLogger(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("unknown log level %q: %w", level, err)
	}
	// Text rather than JSON: the daemon's own logs go to the journal, where a
	// human reads them. The machine-readable output is the snapshot.
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}
