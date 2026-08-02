package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"
)

// The snapshots subcommands work directly on the snapshot directory rather
// than through the daemon, so that they still work on a host where Wake is not
// running — which is exactly the situation when someone has copied a snapshot
// directory to their own machine to look at it.

func snapshotsCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "snapshots",
		Short: "List, inspect and prune snapshots",
		Args:  cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&dir, "dir", "/var/lib/wake/snapshots",
		"snapshot directory")

	list := &cobra.Command{
		Use:   "list",
		Short: "List snapshots, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			snaps, err := listSnapshots(dir)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), snaps)
			}
			if len(snaps) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(),
					"No snapshots in %s. That is the normal state: Wake writes only on trigger.\n", dir)
				return nil
			}
			for _, s := range snaps {
				fmt.Fprintf(cmd.OutOrStdout(), "%-44s %8s  %6d events  %s\n",
					s.ID, humanBytes(s.Bytes), s.Events, s.Trigger)
			}
			return nil
		},
	}

	show := &cobra.Command{
		Use:   "show <id>",
		Short: "Print a snapshot's manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := os.ReadFile(filepath.Join(dir, args[0], "manifest.json"))
			if err != nil {
				return fmt.Errorf("reading the manifest for %q: %w", args[0], err)
			}
			var pretty any
			if err := json.Unmarshal(b, &pretty); err != nil {
				return fmt.Errorf("the manifest is not valid JSON: %w", err)
			}
			return writeJSON(cmd.OutOrStdout(), pretty)
		},
	}

	var keep int
	var maxBytes string
	var dryRun bool
	prune := &cobra.Command{
		Use:   "prune",
		Short: "Delete the oldest snapshots to fit the retention bounds",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Deleting evidence is not something to do by accident, so prune
			// defaults to showing what it would remove.
			if !dryRun {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"Refusing to delete without --yes; showing what would be removed.")
			}
			snaps, err := listSnapshots(dir)
			if err != nil {
				return err
			}
			for i, s := range snaps {
				if keep > 0 && i >= keep {
					fmt.Fprintf(cmd.OutOrStdout(), "would remove %s (%s)\n", s.ID, humanBytes(s.Bytes))
				}
			}
			return nil
		},
	}
	prune.Flags().IntVar(&keep, "keep", 0, "keep this many newest snapshots")
	prune.Flags().StringVar(&maxBytes, "max-size", "", "keep at most this total size (e.g. 2GiB)")
	prune.Flags().BoolVar(&dryRun, "yes", false, "actually delete, rather than listing")

	cmd.AddCommand(list, show, prune)
	return cmd
}

// snapshotSummary is the one-line view of a snapshot, read from its manifest.
type snapshotSummary struct {
	ID      string    `json:"id"`
	Path    string    `json:"path"`
	Bytes   int64     `json:"bytes"`
	Events  int       `json:"events"`
	Trigger string    `json:"trigger"`
	Written time.Time `json:"written"`
}

func listSnapshots(dir string) ([]snapshotSummary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the snapshot directory %s: %w", dir, err)
	}

	var out []snapshotSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		s := snapshotSummary{ID: e.Name(), Path: path}

		if fi, err := e.Info(); err == nil {
			s.Written = fi.ModTime()
		}
		s.Bytes = dirSize(path)

		// A snapshot whose manifest is unreadable is still listed: a
		// half-written or corrupted snapshot is exactly the sort of thing an
		// operator needs to be told about rather than have hidden.
		if b, err := os.ReadFile(filepath.Join(path, "manifest.json")); err == nil {
			var m struct {
				Trigger struct {
					Type   string `json:"type"`
					Reason string `json:"reason"`
				} `json:"trigger"`
				EventCount int `json:"event_count"`
			}
			if json.Unmarshal(b, &m) == nil {
				s.Trigger = m.Trigger.Type
				if m.Trigger.Reason != "" {
					s.Trigger += ": " + m.Trigger.Reason
				}
				s.Events = m.EventCount
			}
		} else {
			s.Trigger = "(manifest unreadable)"
		}
		out = append(out, s)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func dirSize(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a partial size beats no size
		}
		if fi, err := d.Info(); err == nil {
			total += fi.Size()
		}
		return nil
	})
	return total
}
