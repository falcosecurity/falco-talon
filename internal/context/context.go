package context

import (
	"context"
	"fmt"

	"github.com/falco-talon/falco-talon/internal/context/aws"
	"github.com/falco-talon/falco-talon/internal/otlp/traces"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/falco-talon/falco-talon/internal/context/kubernetes"
	"github.com/falco-talon/falco-talon/internal/events"
)

func GetContext(ctx context.Context, source string, event *events.Event) (map[string]interface{}, error) {

	tracer := traces.GetTracer()

	ctx, span := tracer.Start(ctx, "context", oteltrace.WithAttributes(attribute.String("source", source)))
	defer span.End()

	switch source {
	case "aws":
		awsContext, err := aws.GetAwsContext(event)
		if err != nil {
			span.SetStatus(codes.Error, "Failed to add context")
			span.RecordError(err)
			return nil, err
		}
		enrichSpanWithAttributesFromContext(span, awsContext)
		return awsContext, nil
	case "k8snode":
		nodeContext, err := kubernetes.GetNodeContext(event)
		if err != nil {
			span.SetStatus(codes.Error, "Failed to add context")
			span.RecordError(err)
			return nil, err
		}
		enrichSpanWithAttributesFromContext(span, nodeContext)
		return nodeContext, nil
	default:
		return nil, fmt.Errorf("unknown context '%v'", source)
	}
}

func enrichSpanWithAttributesFromContext(span oteltrace.Span, context map[string]interface{}) {
	for k, v := range context {
		span.SetAttributes(attribute.String(k, fmt.Sprintf("%v", v)))
	}
}
