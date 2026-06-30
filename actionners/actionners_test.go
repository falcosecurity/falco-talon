package actionners

import (
	"context"
	"strings"
	"testing"

	"github.com/falcosecurity/falco-talon/configuration"
	"github.com/falcosecurity/falco-talon/internal/events"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/otlp/metrics"
	"github.com/falcosecurity/falco-talon/internal/otlp/traces"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

type requireOutputActionnerStub struct{}

func (a requireOutputActionnerStub) Init() error { return nil }

func (a requireOutputActionnerStub) Run(_ *events.Event, _ *rules.Action) (utils.LogLine, *models.Data, error) {
	return utils.LogLine{Status: utils.SuccessStr}, &models.Data{
		Name:    "artifact.txt",
		Objects: map[string]string{"pod": "demo"},
		Bytes:   []byte("payload"),
	}, nil
}

func (a requireOutputActionnerStub) CheckParameters(_ *rules.Action) error { return nil }

func (a requireOutputActionnerStub) Checks(_ *events.Event, _ *rules.Action) error { return nil }

func (a requireOutputActionnerStub) Information() models.Information {
	return models.Information{
		Name:          "stub",
		FullName:      "tests:stub",
		Category:      "tests",
		RequireOutput: true,
	}
}

func (a requireOutputActionnerStub) Parameters() models.Parameters { return nil }

func TestRunActionReturnsOutputCheckErrors(t *testing.T) {
	configuration.CreateConfiguration("")
	metrics.Init()
	shutdown, err := traces.SetupOTelSDK(context.Background())
	if err != nil {
		t.Fatalf("setup traces: %v", err)
	}
	t.Cleanup(func() {
		_ = shutdown(context.Background())
	})

	previousEnabled := enabledActionners
	enabledActionners = &Actionners{requireOutputActionnerStub{}}
	t.Cleanup(func() {
		enabledActionners = previousEnabled
	})

	action := &rules.Action{
		Name:         "capture",
		Actionner:    "tests:stub",
		Continue:     falseStr,
		IgnoreErrors: falseStr,
		Output: rules.Output{
			Target: "local:file",
			Parameters: map[string]any{
				"destination": t.TempDir() + "/missing",
			},
		},
	}
	rule := &rules.Rule{Name: "rule"}
	event := &events.Event{Output: "event", TraceID: "trace-id"}

	err = runAction(context.Background(), rule, action, event)
	if err == nil {
		t.Fatal("expected output checks failure to be returned")
	}

	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing destination error, got %v", err)
	}
}
