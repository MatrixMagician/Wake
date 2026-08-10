package snapshot

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Entry is a directory listing entry. It carries only what the writer and
// pruner need (name and directory-ness), so a fake FS can produce entries
// without implementing the full fs.DirEntry interface.
type Entry struct {
	Name  string
	IsDir bool
}

// FS is the filesystem surface the writer and pruner use. The production
// implementation, OSFS, wraps os and path/filepath; tests pass OSFS rooted
// at a t.TempDir() for realistic coverage, or a purpose-built fake to
// exercise error paths that are awkward to provoke on a real filesystem
// (see doc.go for the rationale).
//
// FS intentionally has no notion of "the snapshots root" — every method
// takes a full path — so it stays a thin, general-purpose seam rather than
// growing snapshot-specific behaviour.
type FS interface {
	// MkdirAll creates path and any missing parents with permission perm,
	// mirroring os.MkdirAll.
	MkdirAll(path string, perm fs.FileMode) error
	// WriteFile creates or truncates path and writes data to it in one
	// call, mirroring os.WriteFile.
	WriteFile(path string, data []byte, perm fs.FileMode) error
	// CreateFile opens path for streaming writes, creating it if absent and
	// truncating it if present.
	CreateFile(path string, perm fs.FileMode) (io.WriteCloser, error)
	// Rename renames oldpath to newpath. Used for the writer's final
	// atomic publish step, so implementations must offer at least the
	// atomicity POSIX rename(2) gives within one filesystem.
	Rename(oldpath, newpath string) error
	// RemoveAll removes path and everything under it. Removing a path that
	// does not exist is not an error, mirroring os.RemoveAll.
	RemoveAll(path string) error
	// ReadDir lists the immediate children of path.
	ReadDir(path string) ([]Entry, error)
	// DirSize returns the total size in bytes of every regular file found
	// under path, recursively. Used by the pruner to enforce
	// RetentionSettings.MaxTotalBytes.
	DirSize(path string) (int64, error)
}

// OSFS is the production FS backed by the real filesystem.
type OSFS struct{}

var _ FS = OSFS{}

func (OSFS) MkdirAll(path string, perm fs.FileMode) error { return os.MkdirAll(path, perm) }

func (OSFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (OSFS) CreateFile(path string, perm fs.FileMode) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
}

func (OSFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (OSFS) RemoveAll(path string) error { return os.RemoveAll(path) }

func (OSFS) ReadDir(path string) ([]Entry, error) {
	des, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, len(des))
	for i, de := range des {
		entries[i] = Entry{Name: de.Name(), IsDir: de.IsDir()}
	}
	return entries, nil
}

// DirSize totals the regular files under path, tolerating errors and
// returning whatever it managed to add up. It backs `wake status` and
// `wake snapshots list`, where a partial number beats none and an
// unreadable directory is not worth failing a display over.
//
// The pruner deliberately does not use this. OSFS.DirSize below returns an
// error instead, because pruning decides what to delete: under-counting a
// snapshot there could remove one that was actually within the retention
// bound, and a wrong number is worse than a refusal.
func DirSize(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a partial total beats no total
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func (OSFS) DirSize(path string) (int64, error) {
	var total int64
	err := filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}
