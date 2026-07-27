package checks

import (
	"strings"
	"testing"

	"github.com/falcosecurity/falco-talon/internal/events"
)

// TestCheckRemoteIPDoesNotPanicOnNonStringFields ensures CheckRemoteIP does not
// panic when an IP field is decoded as a non-string value. DecodeEvent uses
// json.Decoder.UseNumber(), so such a field used to panic on the bare
// .(string) assertion instead of being reported as a wrong value.
func TestCheckRemoteIPDoesNotPanicOnNonStringFields(t *testing.T) {
	event, err := events.DecodeEvent(strings.NewReader(`{"output_fields": {"fd.sip": 8080}}`))
	if err != nil {
		t.Fatalf("DecodeEvent returned an unexpected error: %v", err)
	}

	err = CheckRemoteIP(event)
	if err == nil {
		t.Fatal("CheckRemoteIP() returned no error, want an error for a non-IP value")
	}
	if err.Error() != "wrong value for fd.sip" {
		t.Errorf("CheckRemoteIP() error = %q, want %q", err, "wrong value for fd.sip")
	}
}

// TestCheckRemoteIPAcceptsValidAddresses ensures the switch to the safe
// accessor keeps the nominal string case working.
func TestCheckRemoteIPAcceptsValidAddresses(t *testing.T) {
	event, err := events.DecodeEvent(strings.NewReader(`{"output_fields": {"fd.sip": "10.0.0.1", "fd.rip": "192.168.1.1"}}`))
	if err != nil {
		t.Fatalf("DecodeEvent returned an unexpected error: %v", err)
	}

	if err := CheckRemoteIP(event); err != nil {
		t.Errorf("CheckRemoteIP() returned an unexpected error: %v", err)
	}
}
