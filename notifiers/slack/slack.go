package slack

import (
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

var Notify = func(rule *rules.Rule, event *events.Event, status string) {
	if slackconfig.WebhookURL == "" {
		return
	}

	client, err := http.NewClient(slackconfig.WebhookURL)
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("Error with Slack notification: %v", err.Error()))
	}
	err = client.Post(NewPayload(rule, event, status))
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("Error with Slack notification: %v", err.Error()))
	}
}

func NewPayload(rule *rules.Rule, event *events.Event, status string) Payload {
	ruleName := rule.GetName()
	pod := event.GetPod()
	namespace := event.GetNamespace()
	action := rule.GetAction()

	var attachments []Attachment
	var attachment Attachment

	attachment.Text = fmt.Sprintf("Action `%v` from rule `%v` has been successfully triggered for pod `%v` in namespace `%v`", action, ruleName, pod, namespace)

	if slackconfig.Format != "short" {
		var fields []Field
		var field Field

		field.Title = "Rule"
		field.Value = "`" + ruleName + "`"
		field.Short = false
		fields = append(fields, field)
		field.Title = "Pod"
		field.Value = "`" + pod + "`"
		field.Short = true
		fields = append(fields, field)
		field.Title = "Namespace"
		field.Value = "`" + namespace + "`"
		field.Short = true
		fields = append(fields, field)
		field.Title = "Action"
		field.Value = strings.ToUpper("`" + action + "`")
		field.Short = true
		fields = append(fields, field)
		field.Title = "Status"
		field.Value = "`" + status + "`"
		field.Short = true
		fields = append(fields, field)

		if slackconfig.Footer != "" {
			attachment.Footer = slackconfig.Footer
		}

		attachment.Fallback = ""
		attachment.Fields = fields
	}

	var color string
	switch status {
	case "failure":
		color = Red
	case "success":
		color = Green
	case "match":
		color = Blue
	}
	attachment.Color = color

	attachments = append(attachments, attachment)

	s := Payload{
		Username:    slackconfig.Username,
		IconURL:     slackconfig.Icon,
		Attachments: attachments,
	}

	// fmt.Printf("%#v\n", s)

	return s
}
