package events

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

type Event struct {
	TraceID      string
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	Source       string                 `json:"source"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Tags         []interface{}          `json:"tags"`
}

func DecodeEvent(payload io.Reader) (*Event, error) {
	var event Event

	d := json.NewDecoder(payload)
	d.UseNumber()

	err := d.Decode(&event)
	if err != nil {
		return &Event{}, err
	}

	if event.Source == "" {
		event.Source = "syscalls"
	}

	if event.TraceID == "" {
		event.TraceID = uuid.New().String()
	}

	return &event, nil
}

func (event *Event) GetPodName() string {
	if event.OutputFields["k8s.pod.name"] != nil {
		return event.OutputFields["k8s.pod.name"].(string)
	}
	return ""
}

func (event *Event) GetNamespaceName() string {
	if event.OutputFields["k8s.ns.name"] != nil {
		return event.OutputFields["k8s.ns.name"].(string)
	}
	return ""
}

func (event *Event) GetTargetName() string {
	if event.OutputFields["ka.target.name"] != nil {
		return event.OutputFields["ka.target.name"].(string)
	}
	return ""
}

func (event *Event) GetTargetNamespace() string {
	if event.OutputFields["ka.target.namespace"] != nil {
		return event.OutputFields["ka.target.namespace"].(string)
	}
	return ""
}

func (event *Event) GetTargetResource() string {
	if event.OutputFields["ka.target.resource"] != nil {
		return event.OutputFields["ka.target.resource"].(string)
	}
	return ""
}
