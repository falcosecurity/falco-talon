package slack

import (
	"errors"
	"fmt"
	"strings"

	"github.com/falco-talon/falco-talon/notifiers/http"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	Red   string = "#e20b0b"
	Green string = "#23ba47"
	Grey  string = "#a4a8b1"

	successStr string = "success"
	failureStr string = "failure"
	ignoredStr string = "ignored"
)

type Settings struct {
	WebhookURL string `field:"webhook_url"`
	Icon       string `field:"icon" default:"https://upload.wikimedia.org/wikipedia/commons/2/26/Circaetus_gallicus_claw.jpg"`
	Username   string `field:"username" default:"Falco Talon"`
	Footer     string `field:"footer" default:"http://github.com/falco-talon/falco-talon"`
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

var settings *Settings

func Init(fields map[string]interface{}) error {
	settings = new(Settings)
	settings = utils.SetFields(settings, fields).(*Settings)
	if err := checkSettings(settings); err != nil {
		return err
	}
	return nil
}

func Notify(log utils.LogLine) error {
	client := http.DefaultClient()

	err := client.Request(settings.WebhookURL, NewPayload(log))
	if err != nil {
		return err
	}
	return nil
}

func checkSettings(settings *Settings) error {
	if settings.WebhookURL == "" {
		return errors.New("wrong `webhook_url` setting")
	}

	if err := http.CheckURL(settings.WebhookURL); err != nil {
		return err
	}

	return nil
}

func NewPayload(log utils.LogLine) Payload {
	var attachments []Attachment
	var attachment Attachment

	var color string
	switch log.Status {
	case failureStr:
		color = Red
	case successStr:
		color = Green
	case ignoredStr:
		color = Grey
	}
	attachment.Color = color

	text := fmt.Sprintf("[%v][%v] ", log.Status, log.Message)
	if log.Target != "" {
		text += fmt.Sprintf("Target '%v' ", log.Target)
	}
	if log.Action != "" {
		text += fmt.Sprintf("Action '%v' ", log.Action)
	}
	if log.Rule != "" {
		text += fmt.Sprintf("Rule '%v' ", log.Rule)
	}

	text = strings.TrimSuffix(text, " ")

	if settings.Format == "short" {
		attachment.Text = text
		text = ""
	} else {
		var fields []Field
		var field Field

		if log.Rule != "" {
			field.Title = "Rule"
			field.Value = "`" + log.Rule + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.Action != "" {
			field.Title = "Action"
			field.Value = "`" + log.Action + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.Actionner != "" {
			field.Title = "Actionner"
			field.Value = "`" + log.Actionner + "`"
			field.Short = true
			fields = append(fields, field)
		}
		field.Title = "Status"
		field.Value = "`" + log.Status + "`"
		field.Short = true
		fields = append(fields, field)
		if len(log.Objects) > 0 {
			for i, j := range log.Objects {
				field.Title = i
				field.Value = "`" + j + "`"
				field.Short = true
				fields = append(fields, field)
			}
		}
		if log.Event != "" {
			field.Title = "Event"
			field.Value = "`" + log.Event + "`"
			field.Short = false
			fields = append(fields, field)
		}
		field.Title = "Message"
		field.Value = "`" + log.Message + "`"
		field.Short = false
		fields = append(fields, field)
		if log.Error != "" {
			field.Title = "Error"
			field.Value = "`" + log.Error + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.Target != "" {
			field.Title = "Target"
			field.Value = "`" + log.Target + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.TraceID != "" {
			field.Title = "Trace ID"
			field.Value = "`" + log.TraceID + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.Result != "" {
			field.Title = "Result"
			field.Value = "`" + log.Result + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.Output != "" {
			field.Title = "Output"
			field.Value = fmt.Sprintf("```\n%v```", utils.RemoveSpecialCharacters(log.Output))
			field.Short = false
			fields = append(fields, field)
		}

		if settings.Footer != "" {
			attachment.Footer = settings.Footer
		}

		attachment.Fallback = ""
		attachment.Fields = fields
	}

	attachments = append(attachments, attachment)

	s := Payload{
		Text:        text,
		Username:    settings.Username,
		IconURL:     settings.Icon,
		Attachments: attachments,
	}

	return s
}
