package notifiers

import (
	"strings"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/k8sevents"
	"github.com/Issif/falco-talon/notifiers/loki"
	"github.com/Issif/falco-talon/notifiers/slack"
	"github.com/Issif/falco-talon/notifiers/smtp"
	"github.com/Issif/falco-talon/notifiers/webhook"
	"github.com/Issif/falco-talon/utils"
)

type Notifier struct {
	Init         func(fields map[string]interface{}) error
	Notification func(log utils.LogLine) error
	Name         string
}

type Notifiers []*Notifier

var notifiers *Notifiers
var defaultNotifiers *Notifiers

func init() {
	defaultNotifiers = new(Notifiers)
	defaultNotifiers = GetDefaultNotifiers()
	notifiers = new(Notifiers)
}

func GetDefaultNotifiers() *Notifiers {
	if len(*defaultNotifiers) == 0 {
		defaultNotifiers.Add(
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
			&Notifier{
				Name:         "loki",
				Init:         loki.Init,
				Notification: loki.Notify,
			},
		)
	}
	return defaultNotifiers
}

func Init() {
	config := configuration.GetConfiguration()

	specifiedNotifiers := map[string]bool{}

	for _, i := range config.GetDefaultNotifiers() {
		specifiedNotifiers[i] = true
	}
	rules := rules.GetRules()
	for _, i := range *rules {
		for _, j := range i.GetNotifiers() {
			specifiedNotifiers[j] = true
		}
	}

	for i := range specifiedNotifiers {
		for _, j := range *defaultNotifiers {
			if strings.ToLower(i) == j.Name {
				if j.Init != nil {
					if err := j.Init(config.Notifiers[i]); err != nil {
						utils.PrintLog("error", config.LogFormat, utils.LogLine{Notifier: i, Message: "init", Error: err.Error(), Status: "failure"})
						continue
					}
					utils.PrintLog("info", config.LogFormat, utils.LogLine{Notifier: i, Message: "init", Status: "success"})
				}
				notifiers.Add(j)
			}
		}
	}
}

func GetNotifiers() *Notifiers {
	return notifiers
}

func Notify(rule *rules.Rule, action *rules.Action, event *events.Event, log utils.LogLine) {
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

	logN := utils.LogLine{
		Message:   "notification",
		Rule:      rule.GetName(),
		Action:    action.GetName(),
		Actionner: action.GetActionner(),
		TraceID:   event.TraceID,
	}

	for i := range enabledNotifiers {
		if n := GetNotifiers().FindNotifier(i); n != nil {
			logN.Notifier = i
			if err := n.Notification(log); err != nil {
				logN.Status = "failure"
				logN.Error = err.Error()
				utils.PrintLog("error", config.LogFormat, logN)
			} else {
				logN.Status = "success"
				utils.PrintLog("info", config.LogFormat, logN)
			}
		}
	}
}

func (notifiers *Notifiers) FindNotifier(name string) *Notifier {
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
