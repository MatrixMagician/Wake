// Package snapshot writes Wake's incident snapshots: a self-contained
// directory under /var/lib/wake/snapshots/<timestamp>-<trigger>/ containing
// manifest.json, events.jsonl.zst, system.json and a proc/ scrape of the
// triggering process (SPEC.md §2 goal 5, milestones M4/M5). See CONTEXT.md
// for the binding definitions of Snapshot, Trigger and Freeze, and
// docs/snapshot-format.md for the full serialised contract that Sift's
// adapter is written against.
//
// This package owns none of the daemon's live state. It does not import
// internal/ring, internal/config or internal/trigger: callers assemble an
// Input value from whatever they already have (a frozen ring's events, a
// drop report, trigger metadata, a config hash) and call Writer.Write. Every
// filesystem and /proc access goes through the FS, ProcSource and
// SystemInfoSource interfaces, so unit tests exercise the real logic against
// a t.TempDir() and small fakes — no root, no real /proc, no kernel.
//
// Write is atomic: it builds the whole snapshot in a hidden staging
// directory beside the target, then renames it into place in one filesystem
// operation, so a half-written snapshot is never observable as complete.
// Retention pruning (by count and by total size, oldest first) only ever
// considers directories matching the finished-snapshot name pattern, so a
// snapshot currently being written is never a candidate for deletion.
package snapshot
