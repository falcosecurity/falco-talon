// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/falcosecurity/falco-talon/utils"
)

// swapMarker is the symlink name Kubernetes flips on ConfigMap volume updates.
const swapMarker = "..data"

// watchRules watches the given rules files (and their parent directories)
// and invokes reload when they change. reload is debounced on the trailing
// edge: a ConfigMap swap emits a burst of events while "..data" still points
// to the old directory when the first one arrives, so the timer is rearmed
// on every event and only fires once the burst is over.
// done closes the watcher when closed; a nil done channel never stops it.
func watchRules(rulesFiles []string, done <-chan struct{}, reload func()) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		utils.PrintLog(utils.ErrorStr, utils.LogLine{Error: err.Error(), Message: rulesStr})
		return
	}
	defer func() { _ = watcher.Close() }()

	// fsnotify reports event names in cleaned form, so the paths the
	// filter compares against have to be cleaned too.
	files := make([]string, 0, len(rulesFiles))
	for _, i := range rulesFiles {
		files = append(files, filepath.Clean(i))
	}
	rulesFiles = files

	watchRulesFiles := func() {
		for _, i := range rulesFiles {
			// best effort: the inode may be gone while a swap is in
			// flight, the directory watch below is the reliable one
			if err := watcher.Add(i); err != nil {
				utils.PrintLog(utils.WarningStr, utils.LogLine{Error: err.Error(), Message: rulesStr})
			}
			// the parent directory is watched too: Kubernetes updates
			// ConfigMap volumes with a symlink swap and editors save
			// with write-tmp-then-rename, both replace the inode the
			// file watch was on, and only directory events reveal it.
			if err := watcher.Add(filepath.Dir(i)); err != nil {
				utils.PrintLog(utils.ErrorStr, utils.LogLine{Error: err.Error(), Message: rulesStr})
			}
		}
	}
	watchRulesFiles()

	// a nil channel blocks forever in select, so nothing is pending until
	// the first event.
	var debounce <-chan time.Time
	for {
		select {
		case event := <-watcher.Events:
			if !isRulesEvent(event, rulesFiles) {
				continue
			}
			if !isRelevantOp(event) {
				continue
			}
			debounce = time.After(1 * time.Second)
		case <-debounce:
			debounce = nil
			watchRulesFiles()
			reload()
		case err := <-watcher.Errors:
			utils.PrintLog(utils.ErrorStr, utils.LogLine{Error: err.Error(), Message: rulesStr})
		case <-done:
			return
		}
	}
}

// isRulesEvent reports whether the event concerns one of the rules files
// themselves, or the ConfigMap swap marker in their directory.
func isRulesEvent(event fsnotify.Event, rulesFiles []string) bool {
	for _, i := range rulesFiles {
		if event.Name == i {
			return true
		}
		if filepath.Base(event.Name) == swapMarker && filepath.Dir(event.Name) == filepath.Dir(i) {
			return true
		}
	}
	return false
}

// isRelevantOp reports whether the event may carry a content change.
func isRelevantOp(event fsnotify.Event) bool {
	return event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)
}
