package loki

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Issif/falco-talon/notifiers/http"
	"github.com/Issif/falco-talon/utils"
)

// loki:
//   # hostport: "" # http://{domain or ip}:{port}, if not empty, Loki output is enabled
//   # user: "" # user for Grafana Logs
//   # apikey: "" # API Key for Grafana Logs
//   # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
//   # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
//   # checkcert: true # check if ssl certificate of the output is valid (default: true)
//   # tenant: "" # Add the Tenant header
//   # endpoint: "/loki/api/v1/push" # The endpoint URL path, default is "/loki/api/v1/push" more info : https://grafana.com/docs/loki/latest/api/#post-apiprompush
//   # extralabels: "" # comma separated list of fields to use as labels additionally to rule, source, priority, tags and custom_fields
//   # customHeaders: # Custom headers to add in POST, useful for Authentication
//   #   key: value

type Configuration struct {
	HostPort      string            `field:"host_port"`
	User          string            `field:"user"`
	APIKey        string            `field:"api_key"`
	Tenant        string            `field:"tenant"`
	CustomHeaders map[string]string `field:"custom_headers"`
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

var lokiconfig *Configuration

var Init = func(fields map[string]interface{}) error {
	lokiconfig = new(Configuration)
	lokiconfig = utils.SetFields(lokiconfig, fields).(*Configuration)
	return nil
}

var Notify = func(log utils.LogLine) error {
	if lokiconfig.HostPort == "" {
		return errors.New("wrong config")
	}

	if err := http.CheckURL(lokiconfig.HostPort); err != nil {
		return err
	}

	client := http.NewClient("", contentType, "", lokiconfig.CustomHeaders)

	if lokiconfig.User != "" && lokiconfig.APIKey != "" {
		client.SetBasicAuth(lokiconfig.User, lokiconfig.APIKey)
	}

	if lokiconfig.Tenant != "" {
		client.SetHeader("X-Scope-OrgID", lokiconfig.Tenant)
	}

	err := client.Post(lokiconfig.HostPort+"/loki/api/v1/push", NewPayload(log))
	if err != nil {
		return err
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

	if t == "" {
		t = fmt.Sprintf("Action '%v' with Actionner '%v' from Rule '%v' has been successfully triggered", log.Action, log.Actionner, log.Rule)
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
