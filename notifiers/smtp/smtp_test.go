package smtp

import (
	"strings"
	"testing"

	"github.com/falcosecurity/falco-talon/utils"
)

func TestNewPayloadTextFormatIncludesPlainTextBody(t *testing.T) {
	parameters = &Parameters{
		From:   "falco@example.com",
		To:     "user@example.com",
		Format: Text,
	}

	payload, err := NewPayload(utils.LogLine{
		Status:       utils.SuccessStr,
		Message:      "action completed",
		Rule:         "Terminal shell in container",
		Action:       "notify",
		TraceID:      "trace-123",
		Objects:      map[string]string{"Pod": "nginx"},
		Error:        "sample error",
		Result:       "sample result",
		Output:       "sample output",
		OutputTarget: "local:file",
	})
	if err != nil {
		t.Fatalf("NewPayload returned error: %v", err)
	}

	if payload.Body == "" {
		t.Fatal("expected text payload body to be populated")
	}

	for _, part := range []string{
		"Subject: [falco-talon][success][action completed]",
		"From: falco@example.com",
		"To: user@example.com",
		"Status: success",
		"Rule: Terminal shell in container",
		"Action: notify",
		"Pod: nginx",
		"Trace ID: trace-123",
	} {
		if !strings.Contains(payload.Body, part) {
			t.Fatalf("expected payload body to contain %q, got:\n%s", part, payload.Body)
		}
	}
}
