package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/MatrixMagician/wake/internal/ctl"
	"github.com/MatrixMagician/wake/internal/doctor"
	"github.com/MatrixMagician/wake/internal/event"
)

func statusCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show ring occupancy, drops, uptime and active triggers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, dec, err := ctl.Dial(opts.socketPath, ctl.Request{Command: ctl.CmdStatus})
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()

			var resp ctl.Response
			if err := dec.Decode(&resp); err != nil {
				return fmt.Errorf("reading the daemon's reply: %w", err)
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			if opts.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), resp.Status)
			}
			printStatus(cmd.OutOrStdout(), resp.Status)
			return nil
		},
	}
}

// printStatus leads with what is lost. An operator reading this during an
// incident needs to know whether they are looking at the whole picture before
// they need any other number on the page.
func printStatus(w interface{ Write([]byte) (int, error) }, s *ctl.Status) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

	p("wake %s (pid %d), recording for %s", s.Version, s.PID, s.Uptime.Round(time.Second))
	p("")

	total := totalDrops(s.Drops)
	if total == 0 {
		p("Drops:      none — every event the kernel produced is accounted for")
	} else {
		p("Drops:      %d events lost", total)
		for _, boundary := range event.Boundaries {
			classes := s.Drops[string(boundary)]
			var parts []string
			for _, c := range event.Classes {
				if n := classes[string(c)]; n > 0 {
					parts = append(parts, fmt.Sprintf("%s=%d", c, n))
				}
			}
			if len(parts) > 0 {
				p("            %-16s %s", boundary, strings.Join(parts, " "))
			}
		}
	}
	p("")

	p("Ring:       %d/%d events, %s/%s, window %s",
		s.Events, s.MaxEvents, humanBytes(int64(s.Bytes)), humanBytes(int64(s.MaxBytes)),
		s.Window.Round(time.Second))
	if s.OldestEvent != nil && s.NewestEvent != nil {
		p("            covering %s (%s to %s)",
			s.NewestEvent.Sub(*s.OldestEvent).Round(time.Second),
			s.OldestEvent.Format(time.RFC3339), s.NewestEvent.Format(time.RFC3339))
	}
	p("Classes:    %s", strings.Join(s.Classes, ", "))
	p("")

	if len(s.Rules) > 0 {
		p("Triggers:")
		for _, r := range s.Rules {
			line := fmt.Sprintf("  %-20s %-8s cooldown %s", r.Name, r.Type, r.Cooldown)
			if r.LastFired != nil {
				line += fmt.Sprintf(", last fired %s ago",
					time.Since(*r.LastFired).Round(time.Second))
			}
			if r.Suppressed > 0 {
				line += fmt.Sprintf(", %d suppressed by cooldown", r.Suppressed)
			}
			p("%s", line)
		}
		p("")
	}

	p("Snapshots:  %d on disk, %s", s.Snapshots, humanBytes(s.SnapshotBytes))
	if s.LastSnapshot != nil {
		p("            most recent %s ago", time.Since(*s.LastSnapshot).Round(time.Second))
	}
	p("Config:     %s", s.ConfigHash)
}

func totalDrops(r event.DropReport) uint64 {
	var t uint64
	for _, classes := range r {
		for _, n := range classes {
			t += n
		}
	}
	return t
}

func triggerCmd(opts *options) *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "trigger",
		Short: "Take a snapshot now",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, dec, err := ctl.Dial(opts.socketPath,
				ctl.Request{Command: ctl.CmdTrigger, Reason: reason})
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()

			var resp ctl.Response
			if err := dec.Decode(&resp); err != nil {
				return fmt.Errorf("reading the daemon's reply: %w", err)
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			if opts.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), resp.Result)
			}
			if resp.Result == nil || !resp.Result.Accepted {
				msg := "the daemon declined to take a snapshot"
				if resp.Result != nil && resp.Result.Message != "" {
					msg = resp.Result.Message
				}
				return fmt.Errorf("%s", msg)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Snapshot written: %s (%d events)\n",
				resp.Result.Path, resp.Result.Events)
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "",
		"why this snapshot was taken; recorded verbatim in the manifest")
	return cmd
}

func watchCmd(opts *options) *cobra.Command {
	var classes []string
	var unit string
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Tail decoded events live (a tuning aid, not a recorder)",
		Long: "Prints the same JSONL a snapshot contains, so that filters developed\n" +
			"here work unchanged against events.jsonl.zst.\n\n" +
			"watch rate-limits itself rather than competing with the recorder: if it\n" +
			"cannot keep up, its events are dropped and counted at the watch_fanout\n" +
			"boundary, visible in `wake status`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, dec, err := ctl.Dial(opts.socketPath, ctl.Request{
				Command: ctl.CmdWatch, Classes: classes, Unit: unit,
			})
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()

			out := cmd.OutOrStdout()
			for {
				var resp ctl.Response
				if err := dec.Decode(&resp); err != nil {
					return nil // the stream ended, which is how watch normally stops
				}
				if resp.Error != "" {
					return fmt.Errorf("daemon: %s", resp.Error)
				}
				if resp.Event == nil {
					continue
				}
				line, err := resp.Event.MarshalJSONLine()
				if err != nil {
					continue
				}
				fmt.Fprintln(out, string(line))
			}
		},
	}
	cmd.Flags().StringSliceVar(&classes, "class", nil,
		"only these event classes (exec, exit, signal, oom, open, connect)")
	cmd.Flags().StringVar(&unit, "unit", "", "only events attributed to this systemd unit")
	return cmd
}

func doctorCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check whether this host can run Wake, and explain any reason it cannot",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := doctor.Run()
			if opts.jsonOutput {
				if err := writeJSON(cmd.OutOrStdout(), report); err != nil {
					return err
				}
			} else {
				out := cmd.OutOrStdout()
				for _, c := range report.Results {
					mark := "ok  "
					switch {
					case c.OK:
					case c.Fatal:
						mark = "FAIL"
					default:
						mark = "warn"
					}
					fmt.Fprintf(out, "[%s] %-26s %s\n", mark, c.Name, c.Detail)
					if c.Remedy != "" {
						for _, line := range wrap(c.Remedy, 72) {
							fmt.Fprintf(out, "       %s\n", line)
						}
					}
				}
				fmt.Fprintln(out)
				if report.OK() {
					fmt.Fprintln(out, "This host can run Wake.")
				} else {
					fmt.Fprintln(out, "This host cannot run Wake; see the FAIL lines above.")
				}
			}
			if !report.OK() {
				// Exit-code gated so that provisioning scripts can rely on it.
				os.Exit(1)
			}
			return nil
		},
	}
}

func writeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// wrap breaks a remedy into terminal-friendly lines. Remedies are prose and
// are often the most important thing on the page, so they get to be readable.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(lines, line)
}

// humanBytes renders a byte count the way an operator would say it.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
