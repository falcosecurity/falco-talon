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
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Action    string `json:"action"`
	Status    string `json:"status"`
}

var webhookConfig *Configuration

var Init = func(fields map[string]interface{}) {
	webhookConfig = new(Configuration)
	webhookConfig = utils.SetFields(webhookConfig, fields).(*Configuration)
}

var Notify = func(rule *rules.Rule, event *events.Event, status string) error {
	if webhookConfig.URL == "" {
		return errors.New("bad config")
	}

	client, err := http.NewClient(webhookConfig.URL)
	if err != nil {
		return err
	}
	err = client.Post(NewWebhookPayload(rule, event, status))
	if err != nil {
		return err
	}
	return nil
}

func NewWebhookPayload(rule *rules.Rule, event *events.Event, status string) Payload {
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
