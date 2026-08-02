package snapshot

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
)

// fakeFS is a small in-memory FS used to exercise error paths and edge
// cases that are awkward or slow to provoke on a real filesystem (e.g.
// "rename fails"). Directories are tracked implicitly by file prefixes,
// which is enough for the writer and pruner's needs (they never rely on an
// empty directory existing on its own).
type fakeFS struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool

	// failRename, when non-nil, is returned by Rename instead of
	// performing it, for testing the writer's atomicity guarantee under a
	// failed publish step.
	failRename error
	// failWriteFile, when non-nil, is returned by WriteFile for any path
	// containing failWriteFilePathSubstr.
	failWriteFile           error
	failWriteFilePathSubstr string
}

func newFakeFS() *fakeFS {
	return &fakeFS{files: map[string][]byte{}, dirs: map[string]bool{}}
}

var _ FS = (*fakeFS)(nil)

func (f *fakeFS) MkdirAll(path string, _ fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirs[path] = true
	return nil
}

func (f *fakeFS) WriteFile(path string, data []byte, _ fs.FileMode) error {
	if f.failWriteFile != nil && strings.Contains(path, f.failWriteFilePathSubstr) {
		return f.failWriteFile
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	f.files[path] = cp
	return nil
}

type fakeWriteCloser struct {
	f    *fakeFS
	path string
	buf  []byte
}

func (w *fakeWriteCloser) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *fakeWriteCloser) Close() error {
	return w.f.WriteFile(w.path, w.buf, 0o600)
}

func (f *fakeFS) CreateFile(path string, _ fs.FileMode) (io.WriteCloser, error) {
	if f.failWriteFile != nil && strings.Contains(path, f.failWriteFilePathSubstr) {
		return nil, f.failWriteFile
	}
	return &fakeWriteCloser{f: f, path: path}, nil
}

func (f *fakeFS) Rename(oldpath, newpath string) error {
	if f.failRename != nil {
		return f.failRename
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := oldpath + "/"
	for p, data := range f.files {
		if strings.HasPrefix(p, prefix) {
			np := newpath + "/" + strings.TrimPrefix(p, prefix)
			f.files[np] = data
			delete(f.files, p)
		}
	}
	for d := range f.dirs {
		if d == oldpath || strings.HasPrefix(d, prefix) {
			nd := newpath + strings.TrimPrefix(d, oldpath)
			f.dirs[nd] = true
			delete(f.dirs, d)
		}
	}
	f.dirs[newpath] = true
	return nil
}

func (f *fakeFS) RemoveAll(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := path + "/"
	for p := range f.files {
		if p == path || strings.HasPrefix(p, prefix) {
			delete(f.files, p)
		}
	}
	for d := range f.dirs {
		if d == path || strings.HasPrefix(d, prefix) {
			delete(f.dirs, d)
		}
	}
	return nil
}

func (f *fakeFS) ReadDir(path string) ([]Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.dirs[path] {
		return nil, fmt.Errorf("readdir %s: %w", path, errors.New("not a directory"))
	}
	seen := map[string]bool{}
	var entries []Entry
	prefix := path + "/"
	for d := range f.dirs {
		if strings.HasPrefix(d, prefix) {
			rest := strings.TrimPrefix(d, prefix)
			name, _, isNested := strings.Cut(rest, "/")
			if isNested {
				continue // not an immediate child
			}
			if !seen[name] {
				seen[name] = true
				entries = append(entries, Entry{Name: name, IsDir: true})
			}
		}
	}
	for p := range f.files {
		if strings.HasPrefix(p, prefix) {
			rest := strings.TrimPrefix(p, prefix)
			if !strings.Contains(rest, "/") && !seen[rest] {
				seen[rest] = true
				entries = append(entries, Entry{Name: rest, IsDir: false})
			}
		}
	}
	return entries, nil
}

func (f *fakeFS) DirSize(path string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var total int64
	prefix := path + "/"
	for p, data := range f.files {
		if strings.HasPrefix(p, prefix) {
			total += int64(len(data))
		}
	}
	return total, nil
}
