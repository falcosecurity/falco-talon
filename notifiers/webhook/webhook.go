package webhook

import (
	"fmt"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/event"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/http"
	"github.com/Issif/falco-talon/utils"
)

type WebhookConfig struct {
	URL string `field:"url"`
}

type WebhookPayload string

var webhookConfig *WebhookConfig

func init() {
	webhookConfig = new(WebhookConfig)
	config := configuration.GetConfiguration()
	webhookConfig = utils.SetField(webhookConfig, config.Notifiers["slack"]).(*WebhookConfig)
}

func NewWebhookPayload(rule *rules.Rule, event *event.Event, status string) WebhookPayload {
	return "body"
}

func Notify(rule *rules.Rule, event *event.Event, status string) {
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
