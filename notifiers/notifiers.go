package notifiers

import (
	"fmt"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/slack"
	"github.com/Issif/falco-talon/notifiers/smtp"
	"github.com/Issif/falco-talon/notifiers/stdout"
	"github.com/Issif/falco-talon/notifiers/webhook"
	"github.com/Issif/falco-talon/utils"
)

type Notifier struct {
	Init         func(fields map[string]interface{})
	Notification func(rule *rules.Rule, event *events.Event, message, status string) error
	Name         string
}

type Notifiers []*Notifier

var notifiers *Notifiers

func Init() {
	notifiers = new(Notifiers)
	notifiers.Add(
		&Notifier{
			Name:         "slack",
			Init:         slack.Init,
			Notification: slack.Notify,
		},
		&Notifier{
			Name:         "stdout",
			Init:         nil,
			Notification: stdout.Notify,
		},
		&Notifier{
			Name:         "webhook",
			Init:         webhook.Init,
			Notification: webhook.Notify,
		},
		&Notifier{
			Name:         "smtp",
			Init:         smtp.Init,
			Notification: smtp.Notify,
		},
	)
	config := configuration.GetConfiguration()
	for _, i := range *GetNotifiers() {
		if i.Init != nil {
			utils.PrintLog("info", fmt.Sprintf("Init Notifier `%v`", i.Name))
			i.Init(config.Notifiers[i.Name])
		}
	}
}

func GetNotifiers() *Notifiers {
	return notifiers
}

func NotifiySuccess(rule *rules.Rule, event *events.Event, message string) {
	notify(rule, event, message, "success")
}
func NotifiyFailure(rule *rules.Rule, event *events.Event, message string) {
	notify(rule, event, message, "failure")
}

func notify(rule *rules.Rule, event *events.Event, message, status string) {
	config := configuration.GetConfiguration()

	if len(rule.Notifiers) == 0 && len(config.DefaultNotifiers) == 0 {
		return
	}

	enabledNotifiers := map[string]bool{}

	for _, i := range config.DefaultNotifiers {
		enabledNotifiers[i] = true
	}
	for _, i := range rule.Notifiers {
		enabledNotifiers[i] = true
	}

	for i := range enabledNotifiers {
		if n := GetNotifiers().GetNotifier(i); n != nil {
			var err error
			switch status {
			case "success":
				err = n.Notification(rule, event, message, "success")
			case "failure":
				err = n.Notification(rule, event, message, "failure")
			}
			if err != nil {
				utils.PrintLog("error", fmt.Sprintf("Notification - Notifier: '%v' Status: 'KO' Error: %v", i, err.Error()))
			} else {
				utils.PrintLog("info", fmt.Sprintf("Notification - Notifier: '%v' Status: 'OK'", i))
			}
		}
	}
}

func (notifiers *Notifiers) GetNotifier(name string) *Notifier {
	for _, i := range *notifiers {
		if i.Name == name {
			return i
		}
	}
	return nil
}

func (notifiers *Notifiers) Add(notifier ...*Notifier) {
	*notifiers = append(*notifiers, notifier...)
}
