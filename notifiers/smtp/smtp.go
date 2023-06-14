package smtp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	textTemplate "text/template"

	sasl "github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"

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
	TLS      bool   `field:"tls" default:"true"`
}

// Payload
type Payload struct {
	To      string
	Subject string
	Body    string
}

var smtpconfig *Configuration

var Init = func(fields map[string]interface{}) error {
	smtpconfig = new(Configuration)
	smtpconfig = utils.SetFields(smtpconfig, fields).(*Configuration)
	return nil
}

var Notify = func(log utils.LogLine) error {
	if smtpconfig.HostPort == "" {
		return errors.New("wrong config")
	}

	payload, err := NewPayload(log)
	if err != nil {
		return err
	}
	err = Send(payload)
	if err != nil {
		return err
	}
	return nil
}

func NewPayload(log utils.LogLine) (Payload, error) {
	var statusPrefix string
	if log.Status == "failure" {
		statusPrefix = "un"
	}

	payload := Payload{
		To:      fmt.Sprintf("To: %v", smtpconfig.To),
		Subject: fmt.Sprintf("Subject: [falco] Action `%v` from rule `%v` has been %vsuccessfully triggered", log.Action, log.Rule, statusPrefix),
		Body:    "MIME-version: 1.0;\n",
	}

	if smtpconfig.Format != Text {
		payload.Body += "Content-Type: multipart/alternative; boundary=4t74weu9byeSdJTM\n\n\n--4t74weu9byeSdJTM\n"
	}

	payload.Body += "Content-Type: text/plain; charset=\"UTF-8\";\n\n"

	var err error

	ttmpl := textTemplate.New(Text)
	ttmpl, err = ttmpl.Parse(plaintextTmpl)
	if err != nil {
		return Payload{}, err
	}
	var outtext bytes.Buffer
	err = ttmpl.Execute(&outtext, log)
	if err != nil {
		return Payload{}, err
	}
	payload.Body += outtext.String()

	if smtpconfig.Format == Text {
		return payload, nil
	}

	payload.Body += "--4t74weu9byeSdJTM\nContent-Type: text/html; charset=\"UTF-8\";\n\n"

	htmpl := textTemplate.New("html")
	htmpl, err = htmpl.Parse(htmlTmpl)
	if err != nil {
		return Payload{}, err
	}
	var outhtml bytes.Buffer
	log.Output = strings.ReplaceAll(utils.RemoveSpecialCharacters(log.Output), "\n", "<br>")
	err = htmpl.Execute(&outhtml, log)
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

	smtpClient, err := smtp.Dial(smtpconfig.HostPort)
	if err != nil {
		return err
	}
	if smtpconfig.TLS {
		tlsCfg := &tls.Config{
			ServerName: strings.Split(smtpconfig.HostPort, ":")[0],
			MinVersion: tls.VersionTLS12,
		}
		if err = smtpClient.StartTLS(tlsCfg); err != nil {
			return err
		}
	}

	err = smtpClient.Auth(auth)
	if err != nil {
		return err
	}
	err = smtpClient.SendMail(smtpconfig.From, to, strings.NewReader(body))
	if err != nil {
		return err
	}
	return nil
}
