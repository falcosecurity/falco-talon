package notifier

import (
	"fmt"

	"github.com/Issif/falco-talon/internal/configuration"
	"github.com/Issif/falco-talon/internal/utils"
)

const (
	Red   string = "#e20b0b"
	Green string = "#23ba47"
	Blue  string = "#206cff"
	// DefaultFooter        = "https://github.com/Issif/falco-talon"
)

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
type SlackPayload struct {
	Text        string       `json:"text,omitempty"`
	Username    string       `json:"username,omitempty"`
	IconURL     string       `json:"icon_url,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

func NewSlackPayload(rule, action, pod, namespace, status string) SlackPayload {
	// var fields []Field
	// var field Field

	// field.Title = "Rule"
	// field.Value = "`" + rule + "`"
	// field.Short = false
	// fields = append(fields, field)
	// field.Title = "Pod"
	// field.Value = "`" + pod + "`"
	// field.Short = true
	// fields = append(fields, field)
	// field.Title = "Namespace"
	// field.Value = "`" + namespace + "`"
	// field.Short = true
	// fields = append(fields, field)
	// field.Title = "Action"
	// field.Value = strings.ToUpper("`" + action + "`")
	// field.Short = true
	// fields = append(fields, field)
	// field.Title = "Status"
	// field.Value = "`" + status + "`"
	// field.Short = true
	// fields = append(fields, field)

	var attachments []Attachment
	var attachment Attachment

	attachment.Text = fmt.Sprintf("Action `%v` of rule `%v ` has been successfully triggered\n for pod `%v` in namespace `%v`", action, rule, pod, namespace)

	// attachment.Footer = DefaultFooter
	config := configuration.GetConfiguration()
	// if config.Notifiers.Slack.Footer != "" {
	// 	attachment.Footer = config.Notifiers.Slack.Footer
	// }

	attachment.Fallback = ""
	// attachment.Fields = fields

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

	s := SlackPayload{
		Username:    config.Notifiers.Slack.Username,
		IconURL:     config.Notifiers.Slack.Icon,
		Attachments: attachments,
	}

	fmt.Printf("%#v\n", s)

	return s
}

func SlackPost(rule, action, pod, namespace, status string) {
	config := configuration.GetConfiguration()
	client, err := NewHTTPClient(config.Notifiers.Slack.WebhookURL)
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("Error with Slack notification: %v", err.Error()))
	}
	err = client.Post(NewSlackPayload(rule, action, pod, namespace, status))
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("Error with Slack notification: %v", err.Error()))
	}
}
