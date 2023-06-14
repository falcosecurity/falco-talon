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

var webhookConfig *Configuration

var Init = func(fields map[string]interface{}) error {
	webhookConfig = new(Configuration)
	webhookConfig = utils.SetFields(webhookConfig, fields).(*Configuration)
	return nil
}

var Notify = func(rule *rules.Rule, event *events.Event, log utils.LogLine) error {
	if webhookConfig.URL == "" {
		return errors.New("wrong config")
	}

	client, err := http.NewClient(webhookConfig.URL)
	if err != nil {
		return err
	}
	err = client.Post(log)
	if err != nil {
		return err
	}
	return nil
}
