package utils

import "testing"

func TestSetFieldsSetsMapStringFieldFromMapAny(t *testing.T) {
	type parameters struct {
		CustomHeaders map[string]string `field:"custom_headers"`
	}

	result := SetFields(&parameters{}, map[string]any{
		"custom_headers": map[string]any{
			"Authorization": "Bearer token",
			"X-Retry":       3,
		},
	}).(*parameters)

	if len(result.CustomHeaders) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(result.CustomHeaders))
	}

	if got := result.CustomHeaders["Authorization"]; got != "Bearer token" {
		t.Fatalf("expected Authorization header to be preserved, got %q", got)
	}

	if got := result.CustomHeaders["X-Retry"]; got != "3" {
		t.Fatalf("expected X-Retry header to be stringified, got %q", got)
	}
}

func TestSetFieldsSetsMapStringFieldFromMapString(t *testing.T) {
	type parameters struct {
		CustomHeaders map[string]string `field:"custom_headers"`
	}

	result := SetFields(&parameters{}, map[string]any{
		"custom_headers": map[string]string{
			"X-Test": "value",
		},
	}).(*parameters)

	if got := result.CustomHeaders["X-Test"]; got != "value" {
		t.Fatalf("expected X-Test header to be preserved, got %q", got)
	}
}
