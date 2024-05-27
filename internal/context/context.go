package context

import (
	"fmt"

	"github.com/falco-talon/falco-talon/internal/context/kubernetes"
	"github.com/falco-talon/falco-talon/internal/events"
)

func GetContext(source string, event *events.Event) (map[string]interface{}, error) {
	switch source {
	case "aws":
		return nil, nil
	case "k8snode":
		return kubernetes.GetNodeContext(event)
	default:
		return nil, fmt.Errorf("unknown context '%v'", source)
	}
}
