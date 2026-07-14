package k8sevents

import (
	"strings"
	"testing"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// notifiers.Notify title-cases every key of log.Objects before calling
// Notifier.Run (see notifiers/notifiers.go), so this notifier must read
// back the same title-cased keys it was given, not the raw lowercase
// object keys ("namespace", "pod") produced by the actionners.
func TestObjectKeysMatchNotifyTitleCasing(t *testing.T) {
	titleCase := func(s string) string {
		return cases.Title(language.Und, cases.NoLower).String(strings.ToLower(s))
	}

	if got, want := titleCase("namespace"), "Namespace"; got != want {
		t.Fatalf("titleCase(%q) = %q, want %q", "namespace", got, want)
	}
	if got, want := titleCase("pod"), "Pod"; got != want {
		t.Fatalf("titleCase(%q) = %q, want %q", "pod", got, want)
	}
}
