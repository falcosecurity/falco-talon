// SPDX-License-Identifier: Apache-2.0

package cmd

// The scenario tests (ConfigMap swap / rename save) rely on inotify's
// directory event semantics and only run on Linux (the kqueue backend on
// macOS does not emit directory content events).

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/require"
)

func skipIfNotLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("fsnotify directory events require inotify (Linux)")
	}
}

// setupConfigMapLayout builds a temp dir mimicking a Kubernetes ConfigMap
// volume: rules.yaml is a symlink chain into a versioned "..data" dir.
func setupConfigMapLayout(t *testing.T) (root, rulesFile string) {
	t.Helper()
	root = t.TempDir()
	v1 := filepath.Join(root, "v1")
	require.NoError(t, os.MkdirAll(v1, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(v1, "rules.yaml"), []byte("v1"), 0o600))
	require.NoError(t, os.Symlink(v1, filepath.Join(root, swapMarker)))
	rulesFile = filepath.Join(root, "rules.yaml")
	require.NoError(t, os.Symlink(filepath.Join(root, swapMarker, "rules.yaml"), rulesFile))
	return root, rulesFile
}

// swapConfigMap simulates a kubelet ConfigMap update: build the new version
// dir, then flip the "..data" symlink via a tmp rename, like kubelet does.
func swapConfigMap(t *testing.T, root, content string) {
	t.Helper()
	v2 := filepath.Join(root, "v2")
	require.NoError(t, os.MkdirAll(v2, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(v2, "rules.yaml"), []byte(content), 0o600))
	tmp := filepath.Join(root, swapMarker+"_tmp")
	require.NoError(t, os.Symlink(v2, tmp))
	require.NoError(t, os.Rename(tmp, filepath.Join(root, swapMarker)))
}

func TestIsRulesEvent(t *testing.T) {
	rules := []string{"/etc/talon/rules/rules.yaml"}
	cases := []struct {
		name  string
		event fsnotify.Event
		want  bool
	}{
		{"direct write on the file", fsnotify.Event{Name: "/etc/talon/rules/rules.yaml", Op: fsnotify.Write}, true},
		{"swap marker in same dir", fsnotify.Event{Name: "/etc/talon/rules/..data", Op: fsnotify.Rename}, true},
		{"swap tmp in same dir is excluded", fsnotify.Event{Name: "/etc/talon/rules/..data_tmp", Op: fsnotify.Create}, false},
		{"unrelated file in same dir", fsnotify.Event{Name: "/etc/talon/rules/talon.yaml", Op: fsnotify.Write}, false},
		{"same name elsewhere", fsnotify.Event{Name: "/other/rules.yaml", Op: fsnotify.Write}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, isRulesEvent(c.event, rules))
		})
	}
}

// TestWatchRulesConfigMapSwap is the regression test for the original bug:
// a ConfigMap-style symlink swap must be collapsed into exactly one reload
// on the trailing edge, and that reload must observe the swapped-in content.
func TestWatchRulesConfigMapSwap(t *testing.T) {
	skipIfNotLinux(t)
	root, rulesFile := setupConfigMapLayout(t)

	var calls atomic.Int32
	var seen atomic.Value
	done := make(chan struct{})
	var once sync.Once
	reload := func() {
		calls.Add(1)
		b, _ := os.ReadFile(rulesFile) //nolint:gosec // test-controlled temp path
		seen.Store(string(b))
		once.Do(func() { close(done) })
	}
	go watchRules([]string{rulesFile}, nil, reload)

	// give the watcher a moment to register
	time.Sleep(300 * time.Millisecond)
	swapConfigMap(t, root, "v2")

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reload happened within 5s after the ConfigMap swap")
	}
	require.Equal(t, "v2", seen.Load(), "reload must observe the swapped-in content")

	// the swap emits a burst; the trailing edge must collapse it into one reload
	time.Sleep(2 * time.Second) // debounce is 1s, let it settle
	require.Equal(t, int32(1), calls.Load(), "the burst must produce exactly one reload")
}

// TestWatchRulesDirectWrite covers the plain editor write path.
func TestWatchRulesDirectWrite(t *testing.T) {
	skipIfNotLinux(t)
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesFile, []byte("v1"), 0o600))

	done := make(chan struct{})
	var once sync.Once
	reload := func() { once.Do(func() { close(done) }) }
	go watchRules([]string{rulesFile}, nil, reload)

	time.Sleep(300 * time.Millisecond)
	require.NoError(t, os.WriteFile(rulesFile, []byte("v2"), 0o600))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reload happened within 5s after a direct write")
	}
}

// TestWatchRulesUncleanPathDirectWrite covers rules paths given in unclean
// form (e.g. -r ./rules.yaml): fsnotify reports cleaned event names, so the
// filter must compare cleaned paths or the reload never fires.
func TestWatchRulesUncleanPathDirectWrite(t *testing.T) {
	skipIfNotLinux(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte("v1"), 0o600))
	unclean := filepath.Join(dir, ".", "rules.yaml")

	done := make(chan struct{})
	var once sync.Once
	reload := func() { once.Do(func() { close(done) }) }
	go watchRules([]string{unclean}, nil, reload)

	time.Sleep(300 * time.Millisecond)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte("v2"), 0o600))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reload after a direct write with an unclean rules path")
	}
}

// TestWatchRulesRenameSave covers the write-tmp-then-rename editor save.
func TestWatchRulesRenameSave(t *testing.T) {
	skipIfNotLinux(t)
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesFile, []byte("v1"), 0o600))

	done := make(chan struct{})
	var once sync.Once
	reload := func() { once.Do(func() { close(done) }) }
	go watchRules([]string{rulesFile}, nil, reload)

	time.Sleep(300 * time.Millisecond)
	tmp := filepath.Join(dir, ".rules.yaml.swp")
	require.NoError(t, os.WriteFile(tmp, []byte("v2"), 0o600))
	require.NoError(t, os.Rename(tmp, rulesFile))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reload happened within 5s after a rename save")
	}
}

// TestWatchRulesCancellation covers the done channel: once closed, the
// watcher stops and no further reload fires.
func TestWatchRulesCancellation(t *testing.T) {
	skipIfNotLinux(t)
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesFile, []byte("v1"), 0o600))

	var calls atomic.Int32
	reload := func() { calls.Add(1) }
	done := make(chan struct{})
	go watchRules([]string{rulesFile}, done, reload)

	time.Sleep(300 * time.Millisecond)
	close(done)
	time.Sleep(300 * time.Millisecond)

	require.NoError(t, os.WriteFile(rulesFile, []byte("v2"), 0o600))
	time.Sleep(1500 * time.Millisecond) // debounce is 1s
	require.Equal(t, int32(0), calls.Load(), "no reload must fire after cancellation")
}
