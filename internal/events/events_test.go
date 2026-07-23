package events

import (
	"encoding/json"
	"strings"
	"testing"
)

// A Falco alert is attacker-influenced JSON, so an output field can hold any
// type. The getters used to assert .(string) on the value directly, which
// panicked the (recover-less) consumer goroutine and took the whole process
// down on a single alert carrying a non-string value. These tests pin the
// guarded behaviour.

func TestGetPodNameNonStringValueDoesNotPanic(t *testing.T) {
	var of map[string]any
	if err := json.Unmarshal([]byte(`{"k8s.pod.name": {"nested": "object"}}`), &of); err != nil {
		t.Fatalf("setup: %v", err)
	}
	e := &Event{OutputFields: of}

	// Before the fix this panicked with
	// "interface conversion: interface {} is map[string]interface {}, not string".
	if got := e.GetPodName(); got != "" {
		t.Fatalf("GetPodName() = %q, want empty string for a non-string field", got)
	}
}

func TestGetPodNameStringValue(t *testing.T) {
	e := &Event{OutputFields: map[string]any{"k8s.pod.name": "nginx"}}
	if got := e.GetPodName(); got != "nginx" {
		t.Fatalf("GetPodName() = %q, want %q", got, "nginx")
	}
}

func TestGetRemotePortAcceptsNumericValue(t *testing.T) {
	// Falco emits ports as JSON numbers. Depending on the decode path the value
	// arrives as json.Number (handler, UseNumber) or float64 (consumer,
	// plain json.Unmarshal); both must yield the port string, not a panic.
	t.Run("json.Number", func(t *testing.T) {
		e, err := DecodeEvent(strings.NewReader(`{"output_fields": {"fd.rport": 8080}}`))
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		if got := e.GetRemotePort(); got != "8080" {
			t.Fatalf("GetRemotePort() = %q, want %q", got, "8080")
		}
	})
	t.Run("float64", func(t *testing.T) {
		var of map[string]any
		if err := json.Unmarshal([]byte(`{"fd.rport": 8080}`), &of); err != nil {
			t.Fatalf("setup: %v", err)
		}
		e := &Event{OutputFields: of}
		if got := e.GetRemotePort(); got != "8080" {
			t.Fatalf("GetRemotePort() = %q, want %q", got, "8080")
		}
	})
}

func TestGetRemoteProtocolReadsSourceProtocol(t *testing.T) {
	// The second branch previously re-read fd.rproto, so an alert carrying only
	// the source protocol returned "". It should fall back to fd.sproto.
	e := &Event{OutputFields: map[string]any{"fd.sproto": "tcp"}}
	if got := e.GetRemoteProtocol(); got != "tcp" {
		t.Fatalf("GetRemoteProtocol() = %q, want %q", got, "tcp")
	}
}
