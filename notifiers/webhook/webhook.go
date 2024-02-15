package webhook

import (
	"errors"

	"github.com/Falco-Talon/falco-talon/notifiers/http"
	"github.com/Falco-Talon/falco-talon/utils"
)

type Configuration struct {
	CustomHeaders map[string]string `field:"custom_headers"`
	URL           string            `field:"url"`
	HTTPMethod    string            `field:"http_method" default:"POST"`
	ContentType   string            `field:"content_type" default:"application/json; charset=utf-8"`
	UserAgent     string            `field:"user_agent" default:"Falco-Talon"`
}

var config *Configuration

func Init(fields map[string]interface{}) error {
	config = new(Configuration)
	config = utils.SetFields(config, fields).(*Configuration)
	return nil
}

func CheckParameters(settings map[string]interface{}) error {
	if settings["url"].(string) == "" {
		return errors.New("wrong `url` setting")
	}

	if err := http.CheckURL(settings["url"].(string)); err != nil {
		return err
	}

	return nil
}

func Notify(log utils.LogLine) error {
	client := http.NewClient(
		config.HTTPMethod,
		config.ContentType,
		config.UserAgent,
		config.CustomHeaders,
	)

	err := client.Request(config.URL, log)
	if err != nil {
		return err
	}
	return nil
}
