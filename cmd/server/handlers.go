package main

import (
	"fmt"
	"net/http"

	evt "github.com/Issif/falco-reactionner/internal/event"
	"github.com/Issif/falco-reactionner/internal/rule"
	"github.com/Issif/falco-reactionner/internal/utils"
)

func mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Please send with post http method", http.StatusBadRequest)
		return
	}

	if r.Body == nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		return
	}

	event, err := evt.DecodeEvent(r.Body)
	if err != nil {
		return
	}

	// fmt.Println(decodedEvent)

	rules := rule.GetRules()
	triggeredRules := make([]*rule.Rule, 0)
	for _, i := range *rules {
		if i.CompareEvent(&event) {
			triggeredRules = append(triggeredRules, i)
		}
	}

	// if one "terminate" rule matches, we trigger it and stop
	for _, i := range triggeredRules {
		if i.Action.Name == "terminate" {
			triggerAction(i, &event)
			return
		}
	}
	// if no "terminate" rule matches, we trigger all rules
	for _, i := range triggeredRules {
		if i.Action.Name != "terminate" {
			triggerAction(i, &event)
		}
	}
}

func triggerAction(rule *rule.Rule, event *evt.Event) {
	pod, namespace := utils.ExtractPodAndNamespace(event)
	if pod == "" || namespace == "" {
		utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: 'none' (missing pod or namespace)", rule.Name))
		return
	}
	utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: '%v' POD: '%v' NAMESPACE: '%v'", rule.Name, rule.Action.Name, pod, namespace))
	var err error
	switch rule.Action.Name {
	case "terminate":
		err = client.Terminate(pod, namespace, rule.Action.Options)
	case "label":
		err = client.Label(pod, namespace, rule.Action.Labels)
	}
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("ACTION: '%v' POD: '%v' NAMESPACE: '%v' ACTION: '%v' STATUS: 'Fail'", rule.Action.Name, rule.Name, pod, namespace))
	} else {
		utils.PrintLog("info", fmt.Sprintf("ACTION: '%v' POD: '%v' NAMESPACE: '%v' STATUS: 'Success'", rule.Action.Name, pod, namespace))
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
