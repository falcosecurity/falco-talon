package handler

import (
	"fmt"
	"net/http"

	evt "github.com/Issif/falco-talon/internal/event"
	"github.com/Issif/falco-talon/internal/kubernetes"
	ruleengine "github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers"
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

	event, err := evt.DecodeEvent(r.Body)
	if err != nil {
		return
	}

	// fmt.Println(decodedEvent)

	rules := ruleengine.GetRules()
	triggeredRules := make([]*ruleengine.Rule, 0)
	for _, i := range *rules {
		if i.CompareEvent(&event) {
			triggeredRules = append(triggeredRules, i)
		}
	}

	// if one "terminate" rule matches, we trigger it and stop
	for _, i := range triggeredRules {
		if i.Action.Name == "terminate" {
			TriggerAction(i, &event)
			return
		}
	}
	// if no "terminate" rule matches, we trigger all rules
	for _, i := range triggeredRules {
		if i.Action.Name != "terminate" {
			TriggerAction(i, &event)
			if !i.Continue {
				break
			}
		}
	}
}

func TriggerAction(rule *ruleengine.Rule, event *evt.Event) {
	pod := event.GetPod()
	namespace := event.GetNamespace()
	action := rule.GetAction()
	ruleName := rule.GetName()

	client := kubernetes.GetClient()

	if pod == "" || namespace == "" {
		utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: 'none' (missing pod or namespace)", ruleName))
		return
	}
	if _, err := client.GetPod(pod, namespace); err != nil {
		utils.PrintLog("info", fmt.Sprintf("pod '%v' in namespace '%v' doesn't exist (it may have been already terminated)", pod, namespace))
		return
	}
	utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: '%v' POD: '%v' NAMESPACE: '%v'", ruleName, action, pod, namespace))
	var err error
	switch rule.Action.Name {
	case "terminate":
		err = client.Terminate(pod, namespace, rule.Action.Options)
	case "label":
		err = client.Label(pod, namespace, rule.Action.Labels)
	}
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("ACTION: '%v' POD: '%v' NAMESPACE: '%v' ACTION: '%v' STATUS: 'Fail'", action, ruleName, pod, namespace))
		notifiers.RouteNotifications(rule, event, "failure")
	} else {
		utils.PrintLog("info", fmt.Sprintf("ACTION: '%v' POD: '%v' NAMESPACE: '%v' STATUS: 'Success'", action, pod, namespace))
		notifiers.RouteNotifications(rule, event, "success")
	}
}

// PingHandler is a simple handler to test if daemon is UP.
func PingHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("pong\n"))
}

// HealthHandler is a simple handler to test if daemon is UP.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status": "ok"}`))
}
