package events

import (
	"strings"
	"testing"
)

// TestGettersDoNotPanicOnNonStringFields ensures the output-field getters do
// not panic when a field is decoded as a non-string value. DecodeEvent uses
// json.Decoder.UseNumber(), so a numeric field such as fd.rport is a
// json.Number, which used to panic on a bare .(string) assertion.
func TestGettersDoNotPanicOnNonStringFields(t *testing.T) {
	payload := `{
		"output_fields": {
			"fd.rport": 8080,
			"fd.rproto": true,
			"k8s.pod.name": "nginx"
		}
	}`

	event, err := DecodeEvent(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("DecodeEvent returned an unexpected error: %v", err)
	}

	if got := event.GetRemotePort(); got != "8080" {
		t.Errorf("GetRemotePort() = %q, want %q", got, "8080")
	}
	if got := event.GetRemoteProtocol(); got != "true" {
		t.Errorf("GetRemoteProtocol() = %q, want %q", got, "true")
	}
	if got := event.GetPodName(); got != "nginx" {
		t.Errorf("GetPodName() = %q, want %q", got, "nginx")
	}
}

// TestGettersReturnEmptyWhenFieldsMissing ensures the getters return an empty
// string when none of their candidate keys are present.
func TestGettersReturnEmptyWhenFieldsMissing(t *testing.T) {
	event, err := DecodeEvent(strings.NewReader(`{"output_fields": {}}`))
	if err != nil {
		t.Fatalf("DecodeEvent returned an unexpected error: %v", err)
	}

	if got := event.GetPodName(); got != "" {
		t.Errorf("GetPodName() = %q, want empty string", got)
	}
	if got := event.GetNamespaceName(); got != "" {
		t.Errorf("GetNamespaceName() = %q, want empty string", got)
	}
}
