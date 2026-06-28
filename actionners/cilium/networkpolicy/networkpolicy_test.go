package networkpolicy

import "testing"

func TestCreateAllowNamespaceEgressRuleUsesAllowNamespaces(t *testing.T) {
	rule := createAllowNamespaceEgressRule(Parameters{
		AllowNamespaces: []string{"blue-ns", "green-ns"},
	})

	if rule == nil {
		t.Fatal("expected a namespace egress rule when allow_namespaces is configured")
	}

	if len(rule.ToEndpoints) != 1 {
		t.Fatalf("expected one endpoint selector, got %d", len(rule.ToEndpoints))
	}

	selector := rule.ToEndpoints[0].LabelSelector
	if selector == nil {
		t.Fatal("expected namespace rule to define a label selector")
	}

	if len(selector.MatchExpressions) != 1 {
		t.Fatalf("expected one match expression, got %d", len(selector.MatchExpressions))
	}

	expr := selector.MatchExpressions[0]
	if expr.Key != namespaceKey {
		t.Fatalf("expected selector key %q, got %q", namespaceKey, expr.Key)
	}

	if len(expr.Values) != 2 || expr.Values[0] != "blue-ns" || expr.Values[1] != "green-ns" {
		t.Fatalf("expected selector values to preserve configured namespaces, got %#v", expr.Values)
	}
}

