package handler

import (
	"net/http"

	"github.com/Issif/falco-talon/actionners"
	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

const (
	trueStr  string = "true"
	falseStr string = "false"
)

func MainHandler(w http.ResponseWriter, r *http.Request) {
	config := configuration.GetConfiguration()
	if r.Method != http.MethodPost {
		http.Error(w, "Please send with POST http method", http.StatusBadRequest)
		return
	}

	if r.Body == nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		return
	}

	event, err := events.DecodeEvent(r.Body)
	if err != nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		return
	}

	utils.PrintLog("info", config.LogFormat, utils.LogLine{
		Rule:     event.Rule,
		Priority: event.Priority,
		Output:   event.Output,
		Source:   event.Source,
		Message:  "event",
		TraceID:  event.TraceID,
	})

	go func() {
		enabledRules := rules.GetRules()
		triggeredRules := make([]*rules.Rule, 0)
		for _, i := range *enabledRules {
			if i.CompareRule(&event) {
				triggeredRules = append(triggeredRules, i)
			}
		}

		a := actionners.GetActionners()
		// we trigger rules with before=true
		for i, j := range triggeredRules {
			if a.GetActionner(j.GetActionCategory(), j.GetActionName()) == nil {
				continue
			}
			if j.Before == trueStr || j.Before != falseStr && a.GetActionner(j.GetActionCategory(), j.GetActionName()).RunBefore() {
				actionners.Trigger(j, &event)
				triggeredRules = removeAlreadyTriggeredRule(triggeredRules, i)
			}
		}
		// we trigger then rules with continue=false
		for _, i := range triggeredRules {
			if a.GetActionner(i.GetActionCategory(), i.GetActionName()) == nil {
				continue
			}
			if i.Continue == falseStr || i.Continue != trueStr && !a.GetActionner(i.GetActionCategory(), i.GetActionName()).MustContinue() {
				actionners.Trigger(i, &event)
				return
			}
		}
		// we trigger after rules with continue=true and before=false
		for _, i := range triggeredRules {
			if a.GetActionner(i.GetActionCategory(), i.GetActionName()) == nil {
				continue
			}
			actionners.Trigger(i, &event)
		}
	}()
}

// HealthHandler is a simple handler to test if daemon is UP.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status": "ok"}`))
}

func removeAlreadyTriggeredRule(rules []*rules.Rule, index int) []*rules.Rule {
	if index < 0 || index >= len(rules) {
		return rules
	}
	copy(rules[index:], rules[index+1:])
	return rules[:len(rules)-1]
}
