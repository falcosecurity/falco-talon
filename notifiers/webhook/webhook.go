package webhook

import (
	"errors"

	"github.com/Issif/falco-talon/notifiers/http"
	"github.com/Issif/falco-talon/utils"
)

type Configuration struct {
	CustomHeaders map[string]string `field:"custom_headers"`
	URL           string            `field:"url"`
	HTTPMethod    string            `field:"http_method" default:"POST"`
	ContentType   string            `field:"content_type" default:"application/json; charset=utf-8"`
	UserAgent     string            `field:"user_agent" default:"Falco-Talon"`
}

var webhookConfig *Configuration

var Init = func(fields map[string]interface{}) error {
	webhookConfig = new(Configuration)
	webhookConfig = utils.SetFields(webhookConfig, fields).(*Configuration)
	return nil
}

var Notify = func(log utils.LogLine) error {
	if webhookConfig.URL == "" {
		return errors.New("wrong config")
	}
	if err := http.CheckURL(webhookConfig.URL); err != nil {
		return err
	}

	client := http.NewClient(
		webhookConfig.HTTPMethod,
		webhookConfig.ContentType,
		webhookConfig.UserAgent,
		webhookConfig.CustomHeaders,
	)

	err := client.Post(webhookConfig.URL, log)
	if err != nil {
		return err
	}
	return nil
}
