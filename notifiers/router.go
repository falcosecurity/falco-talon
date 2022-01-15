package notifiers

import (
	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/event"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers/slack"
	"github.com/Issif/falco-talon/notifiers/webhook"
)

type Notifier interface {
	Notify(rule *rules.Rule, event *event.Event, status string)
}

var notifiers map[string]func(rule *rules.Rule, event *event.Event, status string)

func init() {
	notifiers = make(map[string]func(rule *rules.Rule, event *event.Event, status string))

	notifiers["slack"] = func(rule *rules.Rule, event *event.Event, status string) { slack.Notify(rule, event, status) }
	notifiers["webhook"] = func(rule *rules.Rule, event *event.Event, status string) { webhook.Notify(rule, event, status) }
}

func RouteNotifications(rule *rules.Rule, event *event.Event, status string) {
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

	for i, _ := range enabledNotifiers {
		notifiers[i](rule, event, status)
	}
}

// func notifierIsEnabled(rule *rules.Rule, notifier string) bool {
// 	config := configuration.GetConfiguration()
// 	for _, i := range config.DefaultNotifiers {
// 		if strings.ToLower(i) == notifier {
// 			return true
// 		}
// 	}
// 	for _, i := range rule.Notifiers {
// 		if strings.ToLower(i) == notifier {
// 			return true
// 		}
// 	}
// 	return false
// }
