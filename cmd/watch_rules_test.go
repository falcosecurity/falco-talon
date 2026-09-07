// SPDX-License-Identifier: Apache-2.0

package cmd

// 场景测试（ConfigMap 交换/重命名保存）依赖 inotify 的目录事件语义，
// 仅在 Linux 上运行（macOS 的 kqueue 后端不产生目录内容事件）。

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
func setupConfigMapLayout(t *testing.T, version string) (root, rulesFile string) {
	t.Helper()
	root = t.TempDir()
	v1 := filepath.Join(root, "v1")
	require.NoError(t, os.MkdirAll(v1, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(v1, "rules.yaml"), []byte("v1"), 0o644))
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
	require.NoError(t, os.MkdirAll(v2, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(v2, "rules.yaml"), []byte(content), 0o644))
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
// a ConfigMap-style symlink swap must trigger a reload, and the reload must
// observe the NEW content (trailing-edge debounce).
func TestWatchRulesConfigMapSwap(t *testing.T) {
	skipIfNotLinux(t)
	root, rulesFile := setupConfigMapLayout(t, "v1")

	var calls atomic.Int32
	var seen atomic.Value
	done := make(chan struct{})
	var once sync.Once
	reload := func() {
		calls.Add(1)
		b, _ := os.ReadFile(rulesFile)
		seen.Store(string(b))
		once.Do(func() { close(done) })
	}
	go watchRules([]string{rulesFile}, reload)

	// give the watcher a moment to register
	time.Sleep(300 * time.Millisecond)
	swapConfigMap(t, root, "v2")

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reload happened within 5s after the ConfigMap swap")
	}
	require.Equal(t, "v2", seen.Load(), "reload must observe the swapped-in content")
}

// TestWatchRulesDirectWrite covers the plain editor write path.
func TestWatchRulesDirectWrite(t *testing.T) {
	skipIfNotLinux(t)
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesFile, []byte("v1"), 0o644))

	done := make(chan struct{})
	var once sync.Once
	reload := func() { once.Do(func() { close(done) }) }
	go watchRules([]string{rulesFile}, reload)

	time.Sleep(300 * time.Millisecond)
	require.NoError(t, os.WriteFile(rulesFile, []byte("v2"), 0o644))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reload happened within 5s after a direct write")
	}
}

// TestWatchRulesRenameSave covers the write-tmp-then-rename editor save.
func TestWatchRulesRenameSave(t *testing.T) {
	skipIfNotLinux(t)
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesFile, []byte("v1"), 0o644))

	done := make(chan struct{})
	var once sync.Once
	reload := func() { once.Do(func() { close(done) }) }
	go watchRules([]string{rulesFile}, reload)

	time.Sleep(300 * time.Millisecond)
	tmp := filepath.Join(dir, ".rules.yaml.swp")
	require.NoError(t, os.WriteFile(tmp, []byte("v2"), 0o644))
	require.NoError(t, os.Rename(tmp, rulesFile))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no reload happened within 5s after a rename save")
	}
}
