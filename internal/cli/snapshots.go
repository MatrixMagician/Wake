package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/MatrixMagician/wake/internal/snapshot"
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
	var maxSize string
	var confirm bool
	prune := &cobra.Command{
		Use:   "prune",
		Short: "Delete the oldest snapshots to fit the retention bounds",
		Long: "Deleting evidence is not something to do by accident, so prune shows what\n" +
			"it would remove and does nothing unless --yes is given. The dry run and\n" +
			"the real thing share one decision path, so they cannot disagree.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			settings := snapshot.RetentionSettings{MaxCount: keep}
			if maxSize != "" {
				n, err := parseSize(maxSize)
				if err != nil {
					return err
				}
				settings.MaxTotalBytes = n
			}
			if settings.MaxCount == 0 && settings.MaxTotalBytes == 0 {
				return errors.New("nothing to prune by: give --keep and/or --max-size")
			}

			res, err := snapshot.NewPruner(dir).Prune(settings, !confirm)
			if err != nil {
				return fmt.Errorf("pruning %s: %w", dir, err)
			}

			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), res)
			}

			out := cmd.OutOrStdout()
			if len(res.Removed) == 0 {
				fmt.Fprintf(out, "Nothing to remove: %d snapshot(s) already fit the bounds.\n",
					len(res.Kept))
				return nil
			}
			verb := "would remove"
			if confirm {
				verb = "removed"
			}
			for _, id := range res.Removed {
				fmt.Fprintf(out, "%s %s\n", verb, id)
			}
			fmt.Fprintf(out, "%s %d snapshot(s), %s freed; %d kept.\n",
				verb, len(res.Removed), humanBytes(res.FreedBytes), len(res.Kept))
			if !confirm {
				fmt.Fprintln(out, "Nothing was deleted. Re-run with --yes to apply.")
			}
			return nil
		},
	}
	prune.Flags().IntVar(&keep, "keep", 0, "keep at most this many newest snapshots")
	prune.Flags().StringVar(&maxSize, "max-size", "",
		"keep at most this total size (e.g. 2GiB, 500MB, 1073741824)")
	prune.Flags().BoolVar(&confirm, "yes", false,
		"actually delete; without this, prune only reports what it would do")

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

// parseSize accepts a byte count with an optional unit suffix, because an
// operator setting a retention budget thinks in gigabytes, not in 2147483648.
// Both SI and binary suffixes are accepted and treated as binary: a retention
// bound is a disk-space guard, and being 7% more conservative than asked is the
// harmless direction to err in.
func parseSize(s string) (int64, error) {
	text := strings.TrimSpace(strings.ToUpper(s))
	if text == "" {
		return 0, errors.New("empty size")
	}

	multiplier := int64(1)
	for _, unit := range []struct {
		suffixes []string
		factor   int64
	}{
		{[]string{"TIB", "TB", "T"}, 1 << 40},
		{[]string{"GIB", "GB", "G"}, 1 << 30},
		{[]string{"MIB", "MB", "M"}, 1 << 20},
		{[]string{"KIB", "KB", "K"}, 1 << 10},
		{[]string{"B"}, 1},
	} {
		matched := false
		for _, suffix := range unit.suffixes {
			if strings.HasSuffix(text, suffix) {
				text = strings.TrimSpace(strings.TrimSuffix(text, suffix))
				multiplier = unit.factor
				matched = true
				break
			}
		}
		if matched {
			break
		}
	}

	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse size %q: expected a number with an "+
			"optional unit such as 2GiB, 500MB or 1073741824", s)
	}
	if value < 0 {
		return 0, fmt.Errorf("size %q is negative", s)
	}
	return int64(value * float64(multiplier)), nil
}
