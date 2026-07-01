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

func TestExtractActionsRulesMergesOutputParametersIntoActionsWithoutPanicking(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	baseRulesFile := filepath.Join(tmpDir, "base-rules.yaml")
	if err := os.WriteFile(baseRulesFile, []byte(`
- action: Capture logs
  actionner: kubernetes:log
`), 0o600); err != nil {
		t.Fatalf("write base rules file: %v", err)
	}

	overrideRulesFile := filepath.Join(tmpDir, "override-rules.yaml")
	if err := os.WriteFile(overrideRulesFile, []byte(`
- action: Capture logs
  output:
    target: aws:s3
    parameters:
      bucket: base-bucket

- rule: Repro
  match:
    rules:
      - Test
  actions:
    - action: Capture logs
  notifiers: []
`), 0o600); err != nil {
		t.Fatalf("write override rules file: %v", err)
	}

	actions, rules, err := extractActionsRules([]string{baseRulesFile, overrideRulesFile})
	if err != nil {
		t.Fatalf("extract rules: %v", err)
	}

	if len(*actions) != 1 {
		t.Fatalf("expected 1 merged action, got %d", len(*actions))
	}

	action := (*actions)[0]
	if action.Output.Target != "aws:s3" {
		t.Fatalf("expected merged output target %q, got %q", "aws:s3", action.Output.Target)
	}

	if got := action.Output.Parameters["bucket"]; got != "base-bucket" {
		t.Fatalf("expected merged output bucket %q, got %#v", "base-bucket", got)
	}

	if len(*rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(*rules))
	}
}
