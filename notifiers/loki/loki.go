package loki

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Issif/falco-talon/notifiers/http"
	"github.com/Issif/falco-talon/utils"
)

type Settings struct {
	CustomHeaders map[string]string `field:"custom_headers"`
	HostPort      string            `field:"host_port"`
	User          string            `field:"user"`
	APIKey        string            `field:"api_key"`
	Tenant        string            `field:"tenant"`
}

type Payload struct {
	Streams []Stream `json:"streams"`
}

type Stream struct {
	Stream map[string]string `json:"stream"`
	Values []Value           `json:"values"`
}

type Value []string

const contentType = "application/json"

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
	if settings.HostPort == "" {
		return errors.New("wrong `host_port` setting")
	}

	if err := http.CheckURL(settings.HostPort); err != nil {
		return err
	}

	client := http.NewClient("", contentType, "", settings.CustomHeaders)

	if settings.User != "" && settings.APIKey != "" {
		client.SetBasicAuth(settings.User, settings.APIKey)
	}

	if settings.Tenant != "" {
		client.SetHeader("X-Scope-OrgID", settings.Tenant)
	}

	err := client.Post(settings.HostPort+"/loki/api/v1/push", NewPayload(log))
	if err != nil {
		return err
	}
	return nil
}

func checkSettings(settings *Settings) error {
	if settings.HostPort == "" {
		return errors.New("wrong `host_port` setting")
	}

	return nil
}

func NewPayload(log utils.LogLine) Payload {
	s := make(map[string]string)

	s["status"] = log.Status
	s["rule"] = strings.ReplaceAll(strings.ToLower(log.Rule), " ", "_")
	s["action"] = strings.ReplaceAll(strings.ToLower(log.Action), " ", "_")
	s["actionner"] = log.Actionner
	s["message"] = log.Message
	s["traceid"] = log.TraceID

	for k, v := range log.Objects {
		s[strings.ToLower(k)] = v
	}

	var t string

	if log.Output != "" {
		t = log.Output
	}
	if log.Result != "" {
		t = log.Result
	}
	if log.Error != "" {
		t = log.Error
	}

	return Payload{Streams: []Stream{
		{
			Stream: s,
			Values: []Value{[]string{
				fmt.Sprintf("%v", time.Now().UnixNano()),
				t,
			}},
		},
	}}
}
