package slack

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/http"
	"github.com/Issif/falco-talon/utils"
)

const (
	Red   string = "#e20b0b"
	Green string = "#23ba47"
	Blue  string = "#206cff"
)

type Configuration struct {
	WebhookURL string `field:"webhookurl"`
	Icon       string `field:"icon" default:"https://upload.wikimedia.org/wikipedia/commons/2/26/Circaetus_gallicus_claw.jpg"`
	Username   string `field:"username" default:"Falco Talon"`
	Footer     string `field:"footer" default:"http://github.com/Issif/falco-talon"`
	Format     string `field:"format" default:"long"`
}

type Field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type Attachment struct {
	Fallback   string  `json:"fallback"`
	Color      string  `json:"color"`
	Text       string  `json:"text,omitempty"`
	Footer     string  `json:"footer,omitempty"`
	FooterIcon string  `json:"footer_icon,omitempty"`
	Fields     []Field `json:"fields"`
}

// Payload
type Payload struct {
	Text        string       `json:"text,omitempty"`
	Username    string       `json:"username,omitempty"`
	IconURL     string       `json:"icon_url,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

var slackconfig *Configuration

var Init = func(fields map[string]interface{}) {
	slackconfig = new(Configuration)
	slackconfig = utils.SetFields(slackconfig, fields).(*Configuration)
}

var Notify = func(rule *rules.Rule, event *events.Event, message, status string) error {
	if slackconfig.WebhookURL == "" {
		return errors.New("wrong config")
	}

	client, err := http.NewClient(slackconfig.WebhookURL)
	if err != nil {
		return err
	}
	err = client.Post(NewPayload(rule, event, message, status))
	if err != nil {
		return err
	}
	return nil
}

func NewPayload(rule *rules.Rule, event *events.Event, message, status string) Payload {
	action := rule.GetAction()
	ruleName := rule.GetName()

	var attachments []Attachment
	var attachment Attachment

	var color, statusPrefix string
	switch status {
	case "failure":
		color = Red
		statusPrefix = "un"
	case "success":
		color = Green
	}
	attachment.Color = color

	attachment.Text = fmt.Sprintf("Action `%v` from rule `%v` has been %vsuccessfully triggered", action, ruleName, statusPrefix)

	if slackconfig.Format != "short" {
		var fields []Field
		var field Field

		field.Title = "Rule"
		field.Value = "`" + ruleName + "`"
		field.Short = false
		fields = append(fields, field)
		fields = append(fields, field)
		field.Title = "Action"
		field.Value = strings.ToUpper("`" + action + "`")
		field.Short = true
		fields = append(fields, field)
		field.Title = "Status"
		field.Value = "`" + status + "`"
		field.Short = true
		fields = append(fields, field)
		field.Title = "Event"
		field.Value = event.Output
		field.Short = false
		fields = append(fields, field)
		field.Title = "Message"
		field.Value = message
		field.Short = false
		fields = append(fields, field)

		if slackconfig.Footer != "" {
			attachment.Footer = slackconfig.Footer
		}

		attachment.Fallback = ""
		attachment.Fields = fields
	}

	attachments = append(attachments, attachment)

	s := Payload{
		Username:    slackconfig.Username,
		IconURL:     slackconfig.Icon,
		Attachments: attachments,
	}

	return s
}
