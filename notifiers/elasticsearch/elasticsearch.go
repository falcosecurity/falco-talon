package elasticsearch

import (
	"errors"
	"time"

	"github.com/Issif/falco-talon/notifiers/http"
	"github.com/Issif/falco-talon/utils"
)

type Settings struct {
	CustomHeaders map[string]string `field:"custom_headers"`
	URL           string            `field:"url"`
	User          string            `field:"user"`
	Password      string            `field:"password"`
	Suffix        string            `field:"suffix" default:"daily"`
	Index         string            `field:"index" default:"falco-talon"`
}

const docType string = "/_doc"

var settings *Settings

var Init = func(fields map[string]interface{}) error {
	settings = new(Settings)
	settings = utils.SetFields(settings, fields).(*Settings)
	if err := checkSettings(settings); err != nil {
		return err
	}
	return nil
}

var Notify = func(log utils.LogLine) error {

	client := http.DefaultClient()

	current := time.Now()
	var u string
	switch settings.Suffix {
	case "none":
		u = settings.URL + "/" + settings.Index + docType
	case "monthly":
		u = settings.URL + "/" + settings.Index + "-" + current.Format("2006.01") + docType
	case "annually":
		u = settings.URL + "/" + settings.Index + "-" + current.Format("2006") + docType
	default:
		u = settings.URL + "/" + settings.Index + "-" + current.Format("2006.01.02") + docType
	}

	log.Time = time.Now().Format(time.RFC3339)

	if err := client.Post(u, log); err != nil {
		return err
	}

	return nil
}

func checkSettings(settings *Settings) error {
	if settings.URL == "" {
		return errors.New("wrong `url` setting")
	}

	if err := http.CheckURL(settings.URL); err != nil {
		return err
	}

	return nil
}
