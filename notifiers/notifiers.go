package notifiers

import (
	"fmt"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/slack"
	"github.com/Issif/falco-talon/notifiers/stdout"
	"github.com/Issif/falco-talon/notifiers/webhook"
	"github.com/Issif/falco-talon/utils"
)

type Notifier struct {
	Name         string
	Init         func(fields map[string]interface{})
	Notification func(rule *rules.Rule, event *events.Event, status string)
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

func Notifiy(rule *rules.Rule, event *events.Event, status string) {
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
			go n.Notification(rule, event, status)
		}
	}
}

func (notifier *Notifier) Trigger(rule *rules.Rule, event *events.Event, status string) {
	notifier.Notification(rule, event, status)
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
