package webhook

import (
	"fmt"

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

var Notify = func(rule *rules.Rule, event *events.Event, status string) {
	if webhookConfig.URL == "" {
		return
	}

	client, err := http.NewHTTPClient(webhookConfig.URL)
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("Error with Webhook notification: %v", err.Error()))
	}
	err = client.Post(NewWebhookPayload(rule, event, status))
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("Error with Slack notification: %v", err.Error()))
	}
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
