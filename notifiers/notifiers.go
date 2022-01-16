package notifiers

import (
	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/event"
	"github.com/Issif/falco-talon/internal/rules"
)

type Notifier func(rule *rules.Rule, event *event.Event, status string)
type Notifiers struct {
	List map[string]Notifier
}

var notifiers *Notifiers

func init() {
	notifiers = new(Notifiers)
	notifiers.List = make(map[string]Notifier)
	// notifiers["slack"] = func(rule *rules.Rule, event *event.Event, status string) { slack.Notify(rule, event, status) }
	// notifiers["webhook"] = func(rule *rules.Rule, event *event.Event, status string) { webhook.Notify(rule, event, status) }
}

func GetNotifiers() *Notifiers {
	return notifiers
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

	// for i := range enabledNotifiers {
	// 	notifiers.List[i](rule, event, status)
	// }
}
