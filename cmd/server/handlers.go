package main

import (
	"fmt"
	"net/http"

	"github.com/Issif/falco-reactionner/internal/event"
	"github.com/Issif/falco-reactionner/internal/rule"
	"github.com/Issif/falco-reactionner/internal/utils"
)

func mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Please send with post http method", http.StatusBadRequest)
		return
	}

	decodedEvent, err := event.DecodeEvent(r.Body)
	if err != nil {
		return
	}

	// fmt.Println(decodedEvent)

	rules := rule.GetRules()
	for _, i := range *rules {
		go func(r *rule.Rule) {
			if r.CompareEvent(&decodedEvent) {
				if namespacePodPresent(&decodedEvent) {
					utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: '%v' POD: '%v' NAMESPACE: '%v'", r.Name, r.Action.Name, decodedEvent.OutputFields["k8s.pod.name"], decodedEvent.OutputFields["k8s.ns.name"]))
				} else {
					utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: 'none' (missing pod or namespace in event)", r.Name))
				}
			}
		}(i)
	}
}

// pingHandler is a simple handler to test if daemon is UP.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong\n"))
}

// healthHandler is a simple handler to test if daemon is UP.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte(`{"status": "ok"}`))
}

func namespacePodPresent(input *event.Event) bool {
	if input.OutputFields["k8s.ns.name"] != nil && input.OutputFields["k8s.pod.name"] != nil {
		return true
	}
	return false
}
