package detect

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchTemplates watches dir recursively and invokes onChange (debounced)
// whenever a template file or a subdirectory changes, so signatures are
// recompiled hot without a restart. It returns immediately after starting the
// watch goroutine, which runs until stop is closed.
//
// Editors and git syncs emit bursts of events; changes are coalesced with a
// short debounce so onChange runs once per settled change.
func WatchTemplates(dir string, stop <-chan struct{}, onChange func(), onError func(error)) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	addTree(w, dir)

	go func() {
		defer w.Close()
		const debounceFor = 400 * time.Millisecond
		var (
			timer  *time.Timer
			timerC <-chan time.Time
		)
		arm := func() {
			if timer != nil {
				timer.Stop()
			}
			timer = time.NewTimer(debounceFor)
			timerC = timer.C
		}
		for {
			select {
			case <-stop:
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				// Watch newly created subdirectories too.
				if ev.Op&fsnotify.Create != 0 {
					if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
						addTree(w, ev.Name)
					}
				}
				if isTemplateEvent(ev) {
					arm()
				}
			case <-timerC:
				timerC = nil
				onChange()
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				if onError != nil {
					onError(err)
				}
			}
		}
	}()
	return nil
}

// isTemplateEvent reports whether an event should trigger a reload: a change to
// a .yaml/.yml file, or a directory-level change (ext == "").
func isTemplateEvent(ev fsnotify.Event) bool {
	if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
		return false
	}
	switch strings.ToLower(filepath.Ext(ev.Name)) {
	case ".yaml", ".yml", "":
		return true
	default:
		return false
	}
}

// addTree adds root and all its subdirectories to the watcher, skipping the
// .git directory of a synced template repo (noisy and irrelevant).
func addTree(w *fsnotify.Watcher, root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			_ = w.Add(p)
		}
		return nil
	})
}
