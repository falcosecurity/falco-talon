package stdout

import (
	"encoding/json"

	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

// Payload
type Payload struct {
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Action    string `json:"action"`
	Status    string `json:"status"`
}

var Notify = func(rule *rules.Rule, event *events.Event, status string) error {
	payload := NewPayload(rule, event, status)
	jsonPayload, _ := json.Marshal(payload)
	utils.PrintLog("info", string(jsonPayload))
	return nil
}

func NewPayload(rule *rules.Rule, event *events.Event, status string) Payload {
	pod := event.GetPod()
	namespace := event.GetNamespace()
	action := rule.GetAction()

	return Payload{
		Pod:       pod,
		Namespace: namespace,
		Action:    action,
		Status:    status,
	}
}
