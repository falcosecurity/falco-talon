package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = oldStdout
	output := <-done
	_ = r.Close()

	return output
}

func TestNotifiersListUsesNotifierNameWhenFullNameIsEmpty(t *testing.T) {
	output := captureStdout(t, func() {
		notifiersListCmd.Run(nil, nil)
	})

	if strings.Contains(output, "---  ---") {
		t.Fatalf("expected notifier list header fallback to avoid empty headers, got output:\n%s", output)
	}

	for _, header := range []string{"--- slack ---", "--- loki ---", "--- elasticsearch ---"} {
		if !strings.Contains(output, header) {
			t.Fatalf("expected notifier list output to contain %q, got output:\n%s", header, output)
		}
	}
}
