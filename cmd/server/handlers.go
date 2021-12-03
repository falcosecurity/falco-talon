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
				if pod, namespace := utils.ExtractPodAndNamespace(&decodedEvent); pod != "" && namespace != "" {
					utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: '%v' POD: '%v' NAMESPACE: '%v'", r.Name, r.Action.Name, pod, namespace))
					switch r.Action.Name {
					case "terminate":
						if err := client.Terminate(pod, namespace, r.Action.Options); err != nil {
							utils.PrintLog("error", fmt.Sprintf("ACTION: '%v' POD: '%v' NAMESPACE: '%v' ACTION: '%v' STATUS: 'Fail'", r.Action.Name, r.Name, pod, namespace))
						} else {
							utils.PrintLog("info", fmt.Sprintf("ACTION: '%v' POD: '%v' NAMESPACE: '%v' STATUS: 'Success'", r.Action.Name, pod, namespace))
						}
					case "label":
					}
				} else {
					utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: 'none' (missing pod or namespace)", r.Name))
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
