package cmd

import (
	"testing"

	ruleengine "github.com/falcosecurity/falco-talon/internal/rules"
)

func TestValidateRulesRejectsUnknownActionner(t *testing.T) {
	rules := &[]*ruleengine.Rule{
		{
			Name: "test-rule",
			Actions: []*ruleengine.Action{
				{
					Name:      "test-action",
					Actionner: "tests:missing",
				},
			},
		},
	}

	if validateRules(rules) {
		t.Fatal("expected validation to reject unknown actionners")
	}
}

func TestValidateRulesRejectsUnknownOutputTarget(t *testing.T) {
	rules := &[]*ruleengine.Rule{
		{
			Name: "test-rule",
			Actions: []*ruleengine.Action{
				{
					Name:      "capture-file",
					Actionner: "kubernetes:download",
					Parameters: map[string]any{
						"file": "/tmp/demo.log",
					},
					Output: ruleengine.Output{
						Target: "tests:missing",
						Parameters: map[string]any{
							"destination": "/tmp",
						},
					},
				},
			},
		},
	}

	if validateRules(rules) {
		t.Fatal("expected validation to reject unknown output targets")
	}
}
