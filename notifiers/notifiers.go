package notifiers

import (
	"strings"

	"github.com/Falco-Talon/falco-talon/configuration"
	"github.com/Falco-Talon/falco-talon/internal/events"
	"github.com/Falco-Talon/falco-talon/internal/rules"
	"github.com/Falco-Talon/falco-talon/metrics"
	"github.com/Falco-Talon/falco-talon/notifiers/elasticsearch"
	"github.com/Falco-Talon/falco-talon/notifiers/k8sevents"
	"github.com/Falco-Talon/falco-talon/notifiers/loki"
	"github.com/Falco-Talon/falco-talon/notifiers/slack"
	"github.com/Falco-Talon/falco-talon/notifiers/smtp"
	"github.com/Falco-Talon/falco-talon/notifiers/webhook"
	"github.com/Falco-Talon/falco-talon/utils"
)

type Notifier struct {
	Init         func(fields map[string]interface{}) error
	Notification func(log utils.LogLine) error
	Name         string
}

type Notifiers []*Notifier

var enabledNotifiers *Notifiers
var availableNotifiers *Notifiers

func init() {
	availableNotifiers = new(Notifiers)
	availableNotifiers = GetAvailableNotifiers()
	enabledNotifiers = new(Notifiers)
}

func GetAvailableNotifiers() *Notifiers {
	if len(*availableNotifiers) == 0 {
		availableNotifiers.Add(
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
			&Notifier{
				Name:         "elasticsearch",
				Init:         elasticsearch.Init,
				Notification: elasticsearch.Notify,
			},
		)
	}
	return availableNotifiers
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
		for _, j := range *availableNotifiers {
			if strings.ToLower(i) == j.Name {
				if j.Init != nil {
					if err := j.Init(config.Notifiers[i]); err != nil {
						utils.PrintLog("error", config.LogFormat, utils.LogLine{Notifier: i, Message: "init", Error: err.Error(), Status: "failure"})
						continue
					}
					utils.PrintLog("info", config.LogFormat, utils.LogLine{Notifier: i, Message: "init", Status: "success"})
				}
				enabledNotifiers.Add(j)
			}
		}
	}
}

func GetNotifiers() *Notifiers {
	return enabledNotifiers
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
				metrics.IncreaseCounter(log)
			} else {
				logN.Status = "success"
				utils.PrintLog("info", config.LogFormat, logN)
				metrics.IncreaseCounter(log)
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
