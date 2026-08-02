package snapshot

import (
	"fmt"
	"sort"
	"strings"
)

// PruneResult reports what Prune did (or, in dry-run mode, would do).
type PruneResult struct {
	// Removed lists the snapshot IDs removed, oldest first.
	Removed []string
	// Kept lists the snapshot IDs retained, oldest first.
	Kept []string
	// FreedBytes is the total size of removed snapshots. In dry-run mode
	// this is the size that *would* be freed.
	FreedBytes int64
}

// Pruner enforces RetentionSettings against an existing snapshots root.
// Separated from Writer (rather than a Writer method) because pruning does
// not need any of the capture machinery — only FS — and a caller may want
// to prune on a schedule independent of any particular write (SPEC.md §2
// goal 5: "retention by count and total size").
type Pruner struct {
	root string
	fs   FS
}

// NewPruner creates a Pruner for the snapshots root at root.
func NewPruner(root string, opts ...PrunerOption) *Pruner {
	p := &Pruner{root: root, fs: OSFS{}}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// PrunerOption configures a Pruner beyond its required root.
type PrunerOption func(*Pruner)

// WithPrunerFS overrides the filesystem implementation. Defaults to OSFS.
func WithPrunerFS(fsys FS) PrunerOption { return func(p *Pruner) { p.fs = fsys } }

// Prune applies settings to the snapshots root, removing the oldest
// snapshots first until both the count and total-size bounds are satisfied.
// When dryRun is true, Prune computes exactly what it would remove but does
// not touch the filesystem, so `wake snapshots prune --dry-run` and the
// real prune share one decision path and can never disagree.
//
// Only entries matching the snapshot ID shape (a directory name produced by
// snapshotID: no leading dot) are candidates; the writer's staging
// directories are named with a leading "." specifically so an in-progress
// write is never a candidate here, even under concurrent access (SPEC.md
// §2 goal 5: "Never delete a snapshot currently being written").
func (p *Pruner) Prune(settings RetentionSettings, dryRun bool) (PruneResult, error) {
	entries, err := p.fs.ReadDir(p.root)
	if err != nil {
		return PruneResult{}, fmt.Errorf("list snapshots root: %w", err)
	}

	type candidate struct {
		id   string
		size int64
	}
	var candidates []candidate
	for _, e := range entries {
		if !e.IsDir || !isSnapshotID(e.Name) {
			continue
		}
		size, err := p.fs.DirSize(p.root + "/" + e.Name)
		if err != nil {
			return PruneResult{}, fmt.Errorf("size snapshot %s: %w", e.Name, err)
		}
		candidates = append(candidates, candidate{id: e.Name, size: size})
	}

	// Oldest first: snapshot IDs are RFC3339-ish-prefixed, so lexical order
	// is chronological order (see id.go).
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].id < candidates[j].id })

	var total int64
	for _, c := range candidates {
		total += c.size
	}

	result := PruneResult{}
	kept := make([]candidate, len(candidates))
	copy(kept, candidates)

	overCount := func() bool {
		return settings.MaxCount > 0 && len(kept) > settings.MaxCount
	}
	overSize := func() bool {
		return settings.MaxTotalBytes > 0 && total > settings.MaxTotalBytes
	}

	for len(kept) > 0 && (overCount() || overSize()) {
		victim := kept[0]
		kept = kept[1:]
		total -= victim.size
		result.Removed = append(result.Removed, victim.id)
		result.FreedBytes += victim.size
	}
	for _, c := range kept {
		result.Kept = append(result.Kept, c.id)
	}

	if !dryRun {
		for _, id := range result.Removed {
			if err := p.fs.RemoveAll(p.root + "/" + id); err != nil {
				return result, fmt.Errorf("remove snapshot %s: %w", id, err)
			}
		}
	}

	return result, nil
}

// isSnapshotID reports whether name looks like a finished-snapshot
// directory rather than a staging directory or unrelated file: it must not
// start with "." (the writer's staging prefix) and must contain the
// "-" separating the timestamp from the trigger type (see snapshotID).
func isSnapshotID(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") {
		return false
	}
	return strings.Contains(name, "-")
}
