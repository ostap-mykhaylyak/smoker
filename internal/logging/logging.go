// Package logging provides the four structured JSON log streams smoker writes
// under /var/log/smoker. There is no dashboard or management API by design:
// all observability and audit happen by reading these files.
//
//	access.log      every request forwarded to the backend (clean)
//	blocked.log     every blocked/challenged request, with template-id + reason
//	backend.log     backend errors: 5xx responses + unreachable/transport failures
//	reputation.log  IP state transitions (clean -> greylisted -> blocked ...)
//	smoker.log      operational logs (startup, reload, internal errors)
//
// Rotation is delegated to external logrotate (SIGHUP reopens files) to keep
// the binary dependency-free. Each stream is an independent slog.Logger with a
// JSON handler.
package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/ostap-mykhaylyak/smoker/internal/paths"
)

// Loggers bundles the four log streams plus the underlying files so they can be
// reopened on SIGHUP (logrotate copytruncate is also supported without reopen).
type Loggers struct {
	Access     *slog.Logger
	Blocked    *slog.Logger
	Backend    *slog.Logger
	Reputation *slog.Logger
	Service    *slog.Logger

	mu    sync.Mutex
	dir   string
	files map[string]*reopenFile
}

// reopenFile wraps an *os.File so we can atomically swap the fd on rotation.
type reopenFile struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

func newReopenFile(path string) (*reopenFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &reopenFile{f: f, path: path}, nil
}

func (r *reopenFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Write(p)
}

func (r *reopenFile) reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	nf, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	old := r.f
	r.f = nf
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (r *reopenFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// Open creates/opens the four log files under dir (default /var/log/smoker).
func Open(dir string) (*Loggers, error) {
	if dir == "" {
		dir = paths.LogDir
	}
	l := &Loggers{dir: dir, files: make(map[string]*reopenFile)}
	mk := func(name string) (*slog.Logger, error) {
		rf, err := newReopenFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		l.files[name] = rf
		h := slog.NewJSONHandler(rf, &slog.HandlerOptions{Level: slog.LevelInfo})
		return slog.New(h), nil
	}
	var err error
	if l.Access, err = mk(paths.AccessLog); err != nil {
		return nil, err
	}
	if l.Blocked, err = mk(paths.BlockedLog); err != nil {
		return nil, err
	}
	if l.Backend, err = mk(paths.BackendLog); err != nil {
		return nil, err
	}
	if l.Reputation, err = mk(paths.ReputationLog); err != nil {
		return nil, err
	}
	if l.Service, err = mk(paths.ServiceLog); err != nil {
		return nil, err
	}
	return l, nil
}

// Reopen re-opens all files; call on SIGHUP after logrotate moves them.
func (l *Loggers) Reopen() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, rf := range l.files {
		if err := rf.reopen(); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes and closes all log files.
func (l *Loggers) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var firstErr error
	for _, rf := range l.files {
		if err := rf.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
