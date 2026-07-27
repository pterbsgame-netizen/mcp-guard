package cfg

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// settle is how long to wait for writing to stop before re-reading.
//
// Applications rewrite these files in bursts, and a config caught mid-write is
// invalid JSON. Re-reading on every event would report a parse error and then
// immediately contradict itself.
const settle = 300 * time.Millisecond

// Watch reports differences from approved as the config files change, until ctx
// is cancelled.
//
// Directories are watched rather than files. A config is usually replaced by
// writing a temporary file and renaming it over the original, which destroys a
// watch on the file itself but leaves a directory watch intact — and a watch
// that silently stops working is worse than no watch.
func Watch(ctx context.Context, approved *Baseline, paths []string, onChange func([]Change)) error {
	if len(paths) == 0 {
		return fmt.Errorf("cfg: nothing to watch")
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("cfg: %w", err)
	}
	defer watcher.Close()

	interesting := make(map[string]bool, len(paths))
	dirs := make(map[string]bool, len(paths))
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		interesting[filepath.Clean(abs)] = true
		dirs[filepath.Dir(abs)] = true
	}
	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			return fmt.Errorf("cfg: watching %s: %w", dir, err)
		}
	}

	var timer <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			return fmt.Errorf("cfg: watch: %w", err)

		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			abs, err := filepath.Abs(ev.Name)
			if err != nil {
				abs = ev.Name
			}
			if !interesting[filepath.Clean(abs)] {
				continue
			}
			timer = time.After(settle)

		case <-timer:
			timer = nil
			current, err := Snapshot(paths)
			if err != nil {
				// Almost always a half-written file. The next event will bring
				// us back; reporting it as tampering would be a lie.
				continue
			}
			if changes := Diff(approved, current); len(changes) > 0 {
				onChange(changes)
			}
		}
	}
}
