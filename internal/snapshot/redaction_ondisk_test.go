package snapshot_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/MatrixMagician/wake/internal/config"
	"github.com/MatrixMagician/wake/internal/event"
	"github.com/MatrixMagician/wake/internal/redact"
	"github.com/MatrixMagician/wake/internal/snapshot"
)

// TestRedactedValuesNeverReachDisk is the M5 acceptance criterion, and the
// strongest form of the privacy guarantee: it does not inspect the redactor's
// output, it inspects the *bytes on disk*, decompressed, and every other file
// in the snapshot directory besides.
//
// The test lives here rather than in internal/redact deliberately. Testing the
// redactor in isolation proves the masking function works; testing the written
// snapshot proves the masking is actually wired into the path that persists
// data, which is the property anyone actually cares about. A refactor that
// silently stopped calling Redact would pass the unit test and fail this one.
func TestRedactedValuesNeverReachDisk(t *testing.T) {
	t.Parallel()

	const (
		awsKey    = "AKIAIOSFODNN7EXAMPLE"
		password  = "hunter2-the-actual-password"
		bearerTok = "Bearer eyJhbGciOiJIUzI1NiJ9.secret-payload.sig"
	)

	cfg := config.Default().Redaction
	cfg.UseDefaultRules = true
	cfg.Rules = append(cfg.Rules, config.RedactionRule{
		Name:    "test-password",
		Pattern: `hunter2-the-actual-password`,
	})

	r, err := redact.New(cfg)
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}

	// Events carrying secrets in every field a secret could plausibly reach.
	now := time.Date(2026, 8, 2, 14, 20, 0, 0, time.UTC)
	events := []event.Event{
		{
			Timestamp: now, Class: event.ClassExec, PID: 100,
			Filename: "/usr/bin/psql",
			Argv:     []string{"psql", "--password=" + password, "--key=" + awsKey},
		},
		{
			Timestamp: now.Add(time.Second), Class: event.ClassExec, PID: 101,
			Filename: "/usr/bin/curl",
			Argv:     []string{"curl", "-H", bearerTok},
		},
		{
			Timestamp: now.Add(2 * time.Second), Class: event.ClassOpen, PID: 102,
			Path: "/home/someone/.aws/" + awsKey,
		},
	}

	for i := range events {
		r.Redact(&events[i])
	}

	root := t.TempDir()
	w := snapshot.NewWriter(root, "test")
	res, err := w.Write(snapshot.Input{
		Events: events,
		Drops:  (&event.Drops{}).Report(),
		Trigger: snapshot.TriggerInfo{
			Type: "manual", Reason: "redaction test", FiredAt: now,
		},
		ConfigHash: "test-hash",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	secrets := map[string]string{
		"AWS access key": awsKey,
		"password":       password,
		"bearer token":   "eyJhbGciOiJIUzI1NiJ9.secret-payload.sig",
	}

	// Walk every byte the snapshot wrote, decompressing where necessary.
	err = filepath.WalkDir(res.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".zst") {
			raw, err = decompress(t, raw)
			if err != nil {
				return err
			}
		}
		for name, secret := range secrets {
			if bytes.Contains(raw, []byte(secret)) {
				t.Errorf("the %s reached disk in %s", name, filepath.Base(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the snapshot: %v", err)
	}

	// The counterpart assertion: prove the events were actually written, so
	// that a snapshot which simply dropped everything cannot pass.
	data, err := os.ReadFile(filepath.Join(res.Path, "events.jsonl.zst"))
	if err != nil {
		t.Fatalf("reading events: %v", err)
	}
	plain, err := decompress(t, data)
	if err != nil {
		t.Fatalf("decompressing events: %v", err)
	}

	if n := bytes.Count(plain, []byte("\n")); n != len(events) {
		t.Errorf("wrote %d event lines, want %d; a snapshot that dropped "+
			"everything would pass the redaction check vacuously", n, len(events))
	}
	if !bytes.Contains(plain, []byte("REDACTED")) {
		t.Error("no redaction marker on disk; a reader must be able to tell " +
			"that masking happened rather than see plausible-looking rubbish")
	}
	if !bytes.Contains(plain, []byte("psql")) {
		t.Error("redaction removed the surrounding context as well as the secret")
	}
}

// decompress expands a zstd blob. It exists so that the assertions above read
// as assertions rather than as codec plumbing.
func decompress(t *testing.T, b []byte) ([]byte, error) {
	t.Helper()
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(b, nil)
}
