package smtp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	textTemplate "text/template"

	sasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	"github.com/Issif/falco-talon/utils"
)

const (
	Red   string = "#e20b0b"
	Green string = "#23ba47"
	Grey  string = "#a4a8b1"
	Text  string = "text"

	rfc2822 string = "Mon Jan 02 15:04:05 -0700 2006"

	successStr string = "success"
	failureStr string = "failure"
	ignoredStr string = "ignored"
)

type Configuration struct {
	HostPort string `field:"host_port"`
	User     string `field:"user"`
	Password string `field:"password"`
	From     string `field:"from"`
	To       string `field:"to"`
	Format   string `field:"format" default:"html"`
	TLS      bool   `field:"tls" default:"false"`
}

// Payload
type Payload struct {
	From    string
	To      string
	Subject string
	Body    string
	Mime    string
	Date    string
}

var smtpconfig *Configuration

var Init = func(fields map[string]interface{}) error {
	smtpconfig = new(Configuration)
	smtpconfig = utils.SetFields(smtpconfig, fields).(*Configuration)
	return nil
}

var Notify = func(log utils.LogLine) error {
	if smtpconfig.HostPort == "" {
		return errors.New("wrong host_port")
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
	var status string
	switch log.Status {
	case failureStr:
		status = "unsuccessfully triggered"
	case successStr:
		status = "successfully triggered"
	case ignoredStr:
		status = ignoredStr
	}

	payload := Payload{
		From:    fmt.Sprintf("From: %v", smtpconfig.From),
		To:      fmt.Sprintf("To: %v", smtpconfig.To),
		Subject: fmt.Sprintf("Subject: [falco] Action `%v` from rule `%v` has been %v", log.Action, log.Rule, status),
		Mime:    "MIME-version: 1.0;",
		Date:    "Date: " + time.Now().Format(rfc2822),
	}

	if smtpconfig.Format != Text {
		payload.Mime += "\nContent-Type: multipart/alternative; boundary=4t74weu9byeSdJTM\n\n\n--4t74weu9byeSdJTM"
	}

	payload.Mime += "\nContent-Type: text/plain; charset=\"UTF-8\";\n\n"

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

	if smtpconfig.Format == Text {
		return payload, nil
	}

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

	payload.Body = fmt.Sprintf("%v\n%v\n%v\n%v\n%v\n%v\n\n%v",
		payload.From,
		payload.To,
		payload.Date,
		payload.Mime,
		outtext.String(),
		"--4t74weu9byeSdJTM\nContent-Type: text/html; charset=\"UTF-8\";",
		outhtml.String(),
	)

	return payload, nil
}

func Send(payload Payload) error {
	to := strings.Split(strings.ReplaceAll(smtpconfig.To, " ", ""), ",")
	auth := sasl.NewPlainClient("", smtpconfig.User, smtpconfig.Password)

	smtpClient, err := gosmtp.Dial(smtpconfig.HostPort)
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
	err = smtpClient.SendMail(smtpconfig.From, to, strings.NewReader(payload.Body))
	if err != nil {
		return err
	}
	return nil
}
