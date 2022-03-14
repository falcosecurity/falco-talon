package smtp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	htmlTemplate "html/template"
	textTemplate "text/template"

	sasl "github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"

	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

const (
	Red   string = "#e20b0b"
	Green string = "#23ba47"
	Blue  string = "#206cff"
	Text  string = "text"
)

type Configuration struct {
	HostPort string `field:"hostport"`
	User     string `field:"user"`
	Password string `field:"password"`
	From     string `field:"from"`
	To       string `field:"to"`
	Format   string `field:"format" default:"html"`
}

// Payload
type Payload struct {
	To      string
	Subject string
	Body    string
}

var smtpconfig *Configuration

var Init = func(fields map[string]interface{}) {
	smtpconfig = new(Configuration)
	smtpconfig = utils.SetFields(smtpconfig, fields).(*Configuration)
}

var Notify = func(rule *rules.Rule, event *events.Event, message, status string) error {
	if smtpconfig.HostPort == "" {
		return errors.New("wrong config")
	}

	payload, err := NewPayload(rule, event, message, status)
	if err != nil {
		return err
	}
	err = Send(payload)
	if err != nil {
		return err
	}
	return nil
}

type templateData struct {
	Rule    string
	Action  string
	Event   string
	Message string
	Status  string
}

func NewPayload(rule *rules.Rule, event *events.Event, message, status string) (Payload, error) {
	ruleName := rule.GetName()
	action := rule.GetAction()

	var statusPrefix string
	if status == "failure" {
		statusPrefix = "un"
	}

	payload := Payload{
		To:      fmt.Sprintf("To: %v", smtpconfig.To),
		Subject: fmt.Sprintf("Subject: [falco] Action `%v` from rule `%v` has been %vsuccessfully triggered", action, ruleName, statusPrefix),
		Body:    "MIME-version: 1.0;\n",
	}

	if smtpconfig.Format != Text {
		payload.Body += "Content-Type: multipart/alternative; boundary=4t74weu9byeSdJTM\n\n\n--4t74weu9byeSdJTM\n"
	}

	payload.Body += "Content-Type: text/plain; charset=\"UTF-8\";\n\n"

	data := templateData{
		Action:  rule.GetAction(),
		Event:   event.Output,
		Message: message,
		Rule:    rule.GetName(),
		Status:  status,
	}

	var err error

	ttmpl := textTemplate.New(Text)
	ttmpl, err = ttmpl.Parse(plaintextTmpl)
	if err != nil {
		return Payload{}, err
	}
	var outtext bytes.Buffer
	err = ttmpl.Execute(&outtext, data)
	if err != nil {
		return Payload{}, err
	}
	payload.Body += outtext.String()

	if smtpconfig.Format == Text {
		return payload, nil
	}

	payload.Body += "--4t74weu9byeSdJTM\nContent-Type: text/html; charset=\"UTF-8\";\n\n"

	htmpl := htmlTemplate.New("html")
	htmpl, err = htmpl.Parse(htmlTmpl)
	if err != nil {
		return Payload{}, err
	}
	var outhtml bytes.Buffer
	err = htmpl.Execute(&outhtml, data)
	if err != nil {
		return Payload{}, err
	}
	payload.Body += outhtml.String()

	return payload, nil
}

func Send(payload Payload) error {
	to := strings.Split(strings.ReplaceAll(smtpconfig.To, " ", ""), ",")
	auth := sasl.NewPlainClient("", smtpconfig.User, smtpconfig.Password)
	body := payload.To + "\n" + payload.Subject + "\n" + payload.Body

	err := smtp.SendMail(smtpconfig.HostPort, auth, smtpconfig.From, to, strings.NewReader(body))
	if err != nil {
		return err
	}
	return nil
}
