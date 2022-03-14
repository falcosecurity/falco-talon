package stdout

import (
	"encoding/json"

	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

// Payload
type Payload struct {
	Rule    string `json:"rule"`
	Action  string `json:"action"`
	Event   string `json:"event"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

var Notify = func(rule *rules.Rule, event *events.Event, message, status string) error {
	payload := NewPayload(rule, event, message, status)
	jsonPayload, _ := json.Marshal(payload)
	utils.PrintLog("info", string(jsonPayload))
	return nil
}

func NewPayload(rule *rules.Rule, event *events.Event, message, status string) Payload {
	return Payload{
		Rule:    rule.GetName(),
		Action:  rule.GetAction(),
		Event:   event.Output,
		Message: message,
		Status:  status,
	}
}
