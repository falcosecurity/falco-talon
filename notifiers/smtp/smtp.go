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

	"github.com/falco-talon/falco-talon/utils"
)

const (
	Red   string = "#e20b0b"
	Green string = "#23ba47"
	Grey  string = "#a4a8b1"
	Text  string = "text"

	rfc2822 string = "Mon Jan 02 15:04:05 -0700 2006"
)

type Settings struct {
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
	if settings.HostPort == "" {
		return errors.New("wrong `host_port` setting")
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

func checkSettings(settings *Settings) error {
	if settings.HostPort == "" {
		return errors.New("wrong `host_port` setting")
	}

	return nil
}

func NewPayload(log utils.LogLine) (Payload, error) {
	subject := fmt.Sprintf("Subject: [falco-talon][%v][%v] ", log.Status, log.Message)
	if log.Target != "" {
		subject += fmt.Sprintf("Target '%v' ", log.Target)
	}
	if log.Action != "" {
		subject += fmt.Sprintf("Action '%v' ", log.Action)
	}
	if log.Rule != "" {
		subject += fmt.Sprintf("Rule '%v' ", log.Rule)
	}
	subject = strings.TrimSuffix(subject, " ")

	payload := Payload{
		From:    fmt.Sprintf("From: %v", settings.From),
		To:      fmt.Sprintf("To: %v", settings.To),
		Subject: subject,
		Mime:    "MIME-version: 1.0;",
		Date:    "Date: " + time.Now().Format(rfc2822),
	}

	if settings.Format != Text {
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

	if settings.Format == Text {
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
	to := strings.Split(strings.ReplaceAll(settings.To, " ", ""), ",")
	auth := sasl.NewPlainClient("", settings.User, settings.Password)

	var smtpClient *gosmtp.Client
	var err error
	if settings.TLS {
		tlsCfg := &tls.Config{
			ServerName: strings.Split(settings.HostPort, ":")[0],
			MinVersion: tls.VersionTLS12,
		}
		smtpClient, err = gosmtp.DialStartTLS(settings.HostPort, tlsCfg)
	} else {
		smtpClient, err = gosmtp.Dial(settings.HostPort)
	}
	if err != nil {
		return err
	}

	err = smtpClient.Auth(auth)
	if err != nil {
		return err
	}
	err = smtpClient.SendMail(settings.From, to, strings.NewReader(payload.Body))
	if err != nil {
		return err
	}
	return nil
}
