package loki

import (
	"strings"
	"testing"
)

func TestExampleUsesURLSetting(t *testing.T) {
	if !strings.Contains(Example, "url:") {
		t.Fatalf("expected loki example to use url setting, got:\n%s", Example)
	}
	if strings.Contains(Example, "host_port:") {
		t.Fatalf("expected loki example to stop using host_port setting, got:\n%s", Example)
	}
}
