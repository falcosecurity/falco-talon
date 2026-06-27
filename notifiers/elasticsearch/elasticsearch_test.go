package elasticsearch

import (
	"strings"
	"testing"
)

func TestExampleOnlyDocumentsElasticsearchNotifier(t *testing.T) {
	if strings.Contains(Example, "slack:") {
		t.Fatalf("expected elasticsearch example not to include unrelated slack notifier config, got:\n%s", Example)
	}
	if strings.Count(Example, "notifiers:") != 1 {
		t.Fatalf("expected elasticsearch example to contain a single notifiers block, got:\n%s", Example)
	}
}
