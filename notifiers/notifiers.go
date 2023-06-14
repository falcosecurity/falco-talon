package notifiers

import (
	"strings"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/k8sevents"
	"github.com/Issif/falco-talon/notifiers/slack"
	"github.com/Issif/falco-talon/notifiers/smtp"
	"github.com/Issif/falco-talon/notifiers/webhook"
	"github.com/Issif/falco-talon/utils"
)

type Notifier struct {
	Init         func(fields map[string]interface{}) error
	Notification func(rule *rules.Rule, event *events.Event, log utils.LogLine) error
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
						utils.PrintLog("error", config.LogFormat, utils.LogLine{Notifier: i.Name, Error: err.Error()})
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
							utils.PrintLog("error", config.LogFormat, utils.LogLine{Notifier: i.Name, Message: "init", Error: err.Error()})
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

func Notify(rule *rules.Rule, event *events.Event, log utils.LogLine) {
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
			if err := n.Notification(rule, event, log); err != nil {
				utils.PrintLog("error", config.LogFormat, utils.LogLine{Notifier: i, Status: "failure", Error: err.Error(), Rule: rule.GetName(), Action: rule.GetAction(), TraceID: event.TraceID, Message: "notification"})
			} else {
				utils.PrintLog("info", config.LogFormat, utils.LogLine{Notifier: i, Status: "success", Rule: rule.GetName(), Action: rule.GetAction(), TraceID: event.TraceID, Message: "notification"})
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
