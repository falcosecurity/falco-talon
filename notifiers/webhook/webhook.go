package webhook

import (
	"errors"

	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/http"
	"github.com/Issif/falco-talon/utils"
)

type Configuration struct {
	URL string `field:"url"`
}

type Payload struct {
	Rule    string `json:"rule"`
	Action  string `json:"action"`
	Event   string `json:"event"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

var webhookConfig *Configuration

var Init = func(fields map[string]interface{}) {
	webhookConfig = new(Configuration)
	webhookConfig = utils.SetFields(webhookConfig, fields).(*Configuration)
}

var Notify = func(rule *rules.Rule, event *events.Event, message, status string) error {
	if webhookConfig.URL == "" {
		return errors.New("wrong config")
	}

	client, err := http.NewClient(webhookConfig.URL)
	if err != nil {
		return err
	}
	err = client.Post(NewWebhookPayload(rule, event, message, status))
	if err != nil {
		return err
	}
	return nil
}

func NewWebhookPayload(rule *rules.Rule, event *events.Event, message, status string) Payload {
	return Payload{
		Rule:    rule.GetName(),
		Action:  rule.GetAction(),
		Event:   event.Output,
		Message: message,
		Status:  status,
	}
}
