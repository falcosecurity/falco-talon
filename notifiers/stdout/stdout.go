package stdout

import (
	"github.com/Issif/falco-talon/configuration"
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
	config := configuration.GetConfiguration()
	utils.PrintLog("info",
		config.LogFormat,
		utils.LogLine{
			Rule:    rule.GetName(),
			Action:  rule.GetAction(),
			Event:   event.Output,
			Status:  status,
			Message: message,
		})
	return nil
}
