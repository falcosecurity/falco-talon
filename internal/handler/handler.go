package handler

import (
	"net/http"

	yaml "gopkg.in/yaml.v3"

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

	if config.PrintAllEvents {
		utils.PrintLog("info", config.LogFormat, utils.LogLine{
			Message:  "event",
			Event:    event.Rule,
			Priority: event.Priority,
			Output:   event.Output,
			Source:   event.Source,
			TraceID:  event.TraceID,
		})
	}

	go func() {
		enabledRules := rules.GetRules()
		triggeredRules := make([]*rules.Rule, 0)
		for _, i := range *enabledRules {
			if i.CompareRule(event) {
				triggeredRules = append(triggeredRules, i)
			}
		}

		if len(triggeredRules) == 0 {
			return
		}

		if !config.PrintAllEvents {
			utils.PrintLog("info", config.LogFormat, utils.LogLine{
				Message:  "event",
				Event:    event.Rule,
				Priority: event.Priority,
				Output:   event.Output,
				Source:   event.Source,
				TraceID:  event.TraceID,
			})
		}

		for _, i := range triggeredRules {
			utils.PrintLog("info", config.LogFormat, utils.LogLine{
				Message:  "match",
				Rule:     i.GetName(),
				Event:    event.Rule,
				Priority: event.Priority,
				Source:   event.Source,
				TraceID:  event.TraceID,
			})

			for _, a := range i.GetActions() {
				if err := actionners.RunAction(i, a, event); err != nil && !a.IgnoreErrors {
					break
				}
				if a.Continue == falseStr || a.Continue != trueStr && !actionners.GetDefaultActionners().FindActionner(a.GetActionner()).MustDefaultContinue() {
					break
				}
			}

			if i.Continue == falseStr {
				break
			}
		}
	}()
}

// HealthHandler is a simple handler to test if daemon is UP.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status": "ok"}`))
}

// Download the rule files
func RulesHandler(w http.ResponseWriter, _ *http.Request) {
	r := rules.GetRules()
	w.Header().Add("Content-Type", "text/yaml")
	b, _ := yaml.Marshal(r)
	_, _ = w.Write(b)
}
