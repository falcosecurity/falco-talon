package handler

import (
	"fmt"
	"net/http"

	"github.com/Issif/falco-talon/actionners"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

func MainHandler(w http.ResponseWriter, r *http.Request) {
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

	utils.PrintLog("info", fmt.Sprintf("Event - Rule: '%v' Priority: '%v' Output: '%v' Source: '%v'", event.Rule, event.Priority, event.Output, event.Source))

	enabledRules := rules.GetRules()
	triggeredRules := make([]*rules.Rule, 0)
	for _, i := range *enabledRules {
		if i.CompareRule(&event) {
			triggeredRules = append(triggeredRules, i)
		}
	}

	// we trigger first rules with must not continue
	for _, i := range triggeredRules {
		if !i.MustContinue() {
			actionners.Trigger(i, &event)
			return
		}
	}
	// we trigger after rules with continue
	for _, i := range triggeredRules {
		if i.MustContinue() {
			actionners.Trigger(i, &event)
		}
	}
}

// HealthHandler is a simple handler to test if daemon is UP.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status": "ok"}`))
}
