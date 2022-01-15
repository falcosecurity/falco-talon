package slack

import (
	"fmt"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/event"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/http"
	"github.com/Issif/falco-talon/utils"
)

const (
	Red   string = "#e20b0b"
	Green string = "#23ba47"
	Blue  string = "#206cff"
)

type SlackConfig struct {
	WebhookURL string `field:"webhookurl"`
	Footer     string `field:"footer" default:"http://github.com/Issif/falco-talon"`
	Icon       string `field:"icon" default:"https://default"`
	Username   string `field:"username" default:"Falco Talon"`
	Format     string `field:"format" default:"all"`
	// Number     int     `field:"number" default:"10"`
	// Number64   int64   `field:"number64" default:"20"`
	// Boolean    bool    `field:"boolean" default:"false"`
	// Float      float64 `field:"float64" default:"2.5"`
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
	Fields     []Field `json:"fields"`
	Footer     string  `json:"footer,omitempty"`
	FooterIcon string  `json:"footer_icon,omitempty"`
}

// Payload
type SlackPayload struct {
	Text        string       `json:"text,omitempty"`
	Username    string       `json:"username,omitempty"`
	IconURL     string       `json:"icon_url,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

var slackconfig *SlackConfig

func init() {
	slackconfig = new(SlackConfig)
	config := configuration.GetConfiguration()
	slackconfig = utils.SetField(slackconfig, config.Notifiers["slack"]).(*SlackConfig)
}

func NewSlackPayload(rule *rules.Rule, event *event.Event, status string) SlackPayload {
	pod := event.GetPod()
	namespace := event.GetNamespace()
	action := rule.GetAction()

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
		Username:    slackconfig.Username,
		IconURL:     slackconfig.Icon,
		Attachments: attachments,
	}

	fmt.Printf("%#v\n", s)

	return s
}

func Notify(rule *rules.Rule, event *event.Event, status string) {
	if slackconfig.WebhookURL == "" {
		return
	}

	client, err := http.NewHTTPClient(slackconfig.WebhookURL)
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("Error with Slack notification: %v", err.Error()))
	}
	err = client.Post(NewSlackPayload(rule, event, status))
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("Error with Slack notification: %v", err.Error()))
	}
}
