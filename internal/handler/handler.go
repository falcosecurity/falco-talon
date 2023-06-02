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

	enabledRules := rules.GetRules()
	triggeredRules := make([]*rules.Rule, 0)
	for _, i := range *enabledRules {
		if i.CompareRule(&event) {
			triggeredRules = append(triggeredRules, i)
		}
	}

	a := actionners.GetActionners()
	// we trigger rules with before=true
	for _, i := range triggeredRules {
		if i.Before == "true" || a.GetActionner(i.GetActionCategory(), i.GetActionName()).RunBefore() {
			actionners.Trigger(i, &event)
		}
	}
	// we trigger then rules with continue=false
	for _, i := range triggeredRules {
		if i.Continue == falseStr || !a.GetActionner(i.GetActionCategory(), i.GetActionName()).MustContinue() {
			actionners.Trigger(i, &event)
			return
		}
	}
	// we trigger after rules with continue=true
	for _, i := range triggeredRules {
		if i.Continue != falseStr && a.GetActionner(i.GetActionCategory(), i.GetActionName()).MustContinue() {
			actionners.Trigger(i, &event)
		}
	}
}

// HealthHandler is a simple handler to test if daemon is UP.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status": "ok"}`))
}
