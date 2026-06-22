// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractActionsRulesReportsTheBrokenFileName(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	validRulesFile := filepath.Join(tmpDir, "valid-rules.yaml")
	if err := os.WriteFile(validRulesFile, []byte(`
- rule: valid
  description: valid rule
  actions: []
  notifiers: []
  match: {}
`), 0o600); err != nil {
		t.Fatalf("write valid rules file: %v", err)
	}

	brokenRulesFile := filepath.Join(tmpDir, "broken-rules.yaml")
	if err := os.WriteFile(brokenRulesFile, []byte(`
- rule: broken
  description: [
`), 0o600); err != nil {
		t.Fatalf("write broken rules file: %v", err)
	}

	_, _, err := extractActionsRules([]string{validRulesFile, brokenRulesFile})
	if err == nil {
		t.Fatal("expected invalid YAML to return an error")
	}

	if !strings.Contains(err.Error(), brokenRulesFile) {
		t.Fatalf("expected error to mention %q, got %q", brokenRulesFile, err.Error())
	}
}
