package notifiers

import (
	"strings"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/k8sevents"
	"github.com/Issif/falco-talon/notifiers/slack"
	"github.com/Issif/falco-talon/notifiers/smtp"
	"github.com/Issif/falco-talon/notifiers/stdout"
	"github.com/Issif/falco-talon/notifiers/webhook"
	"github.com/Issif/falco-talon/utils"
)

type Notifier struct {
	Init         func(fields map[string]interface{}) error
	Notification func(rule *rules.Rule, event *events.Event, message, status string) error
	Name         string
	initialized  bool
}

type Notifiers []*Notifier

var notifiers *Notifiers

func Init() {
	notifiers = new(Notifiers)
	n := new(Notifiers)
	n.Add(
		&Notifier{
			Name:         "k8sevents",
			Init:         nil,
			Notification: k8sevents.Notify,
		},
		&Notifier{
			Name:         "slack",
			Init:         slack.Init,
			Notification: slack.Notify,
		},
		&Notifier{
			Name:         "smtp",
			Init:         smtp.Init,
			Notification: smtp.Notify,
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
	)
	config := configuration.GetConfiguration()
	for _, i := range *n {
		for _, j := range config.GetDefaultNotifiers() {
			if i.Name == strings.ToLower(j) && !i.initialized {
				i.initialized = true
				utils.PrintLog("info", config.LogFormat, utils.LogLine{Notifier: i.Name, Message: "init"})
				if i.Init != nil {
					if err := i.Init(config.Notifiers[i.Name]); err != nil {
						utils.PrintLog("error", config.LogFormat, utils.LogLine{Notifier: i.Name, Error: err})
						continue
					}
				}
				notifiers.Add(i)
			}
		}
		rules := rules.GetRules()
		for _, j := range *rules {
			for _, k := range j.GetNotifiers() {
				if i.Name == strings.ToLower(k) && !i.initialized {
					i.initialized = true
					if i.Init != nil {
						utils.PrintLog("info", config.LogFormat, utils.LogLine{Notifier: i.Name, Message: "init"})
						if err := i.Init(config.Notifiers[i.Name]); err != nil {
							utils.PrintLog("error", config.LogFormat, utils.LogLine{Notifier: i.Name, Error: err})
							continue
						}
						notifiers.Add(i)
					}
				}
			}
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
				utils.PrintLog("error", config.LogFormat, utils.LogLine{Notifier: i, Error: err, Rule: rule.GetName(), Action: rule.GetAction(), UUID: event.UUID, Message: "notification"})
			} else {
				utils.PrintLog("info", config.LogFormat, utils.LogLine{Notifier: i, Result: "ok", Rule: rule.GetName(), Action: rule.GetAction(), UUID: event.UUID, Message: "notification"})
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
