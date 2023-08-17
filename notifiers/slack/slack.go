package slack

import (
	"errors"
	"fmt"

	"github.com/Issif/falco-talon/notifiers/http"
	"github.com/Issif/falco-talon/utils"
)

const (
	Red   string = "#e20b0b"
	Green string = "#23ba47"
	Grey  string = "#a4a8b1"
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

var Init = func(fields map[string]interface{}) error {
	slackconfig = new(Configuration)
	slackconfig = utils.SetFields(slackconfig, fields).(*Configuration)
	return nil
}

var Notify = func(log utils.LogLine) error {
	if slackconfig.WebhookURL == "" {
		return errors.New("wrong config")
	}

	client, err := http.NewClient(slackconfig.WebhookURL)
	if err != nil {
		return err
	}
	err = client.Post(NewPayload(log))
	if err != nil {
		return err
	}
	return nil
}

func NewPayload(log utils.LogLine) Payload {
	var attachments []Attachment
	var attachment Attachment

	var color, status, resultOrError string
	switch log.Status {
	case "failure":
		color = Red
		status = "unsuccessfully triggered"
		resultOrError = "error"
	case "success":
		color = Green
		status = "successfully triggered"
		resultOrError = "result"
	case "ignored":
		color = Grey
		status = "ignored"
		resultOrError = "result"
	}
	attachment.Color = color

	text := fmt.Sprintf("Action `%v` from rule `%v` has been %v", log.Action, log.Rule, status)

	if slackconfig.Format == "short" {
		attachment.Text = text + fmt.Sprintf(", with %v: `%v`", resultOrError, log.Message)
		text = ""
	} else {
		var fields []Field
		var field Field

		field.Title = "Rule"
		field.Value = "`" + log.Rule + "`"
		field.Short = false
		fields = append(fields, field)
		field.Title = "Action"
		field.Value = "`" + log.Action + "`"
		field.Short = true
		fields = append(fields, field)
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
		field.Title = "Event"
		field.Value = "`" + log.Event + "`"
		field.Short = false
		fields = append(fields, field)
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

		if slackconfig.Footer != "" {
			attachment.Footer = slackconfig.Footer
		}

		attachment.Fallback = ""
		attachment.Fields = fields
	}

	attachments = append(attachments, attachment)

	s := Payload{
		Text:        text,
		Username:    slackconfig.Username,
		IconURL:     slackconfig.Icon,
		Attachments: attachments,
	}

	return s
}
