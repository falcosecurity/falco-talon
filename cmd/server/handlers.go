package main

import (
	"fmt"
	"net/http"

	"github.com/Issif/falco-talon/internal/configuration"
	evt "github.com/Issif/falco-talon/internal/event"
	"github.com/Issif/falco-talon/internal/notifier"
	"github.com/Issif/falco-talon/internal/rule"
	"github.com/Issif/falco-talon/internal/utils"
)

const (
	terminateStr = "terminate"
)

func mainHandler(w http.ResponseWriter, r *http.Request) {
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

	rules := rule.GetRules()
	triggeredRules := make([]*rule.Rule, 0)
	for _, i := range *rules {
		if i.CompareEvent(&event) {
			triggeredRules = append(triggeredRules, i)
		}
	}

	// if one "terminate" rule matches, we trigger it and stop
	for _, i := range triggeredRules {
		if i.Action.Name == terminateStr {
			triggerAction(i, &event)
			return
		}
	}
	// if no "terminate" rule matches, we trigger all rules
	for _, i := range triggeredRules {
		if i.Action.Name != terminateStr {
			triggerAction(i, &event)
			if !i.Continue {
				break
			}
		}
	}
}

func triggerAction(rule *rule.Rule, event *evt.Event) {
	pod, namespace := utils.ExtractPodAndNamespace(event)
	if pod == "" || namespace == "" {
		utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: 'none' (missing pod or namespace)", rule.Name))
		return
	}
	if _, err := client.GetPod(pod, namespace); err != nil {
		utils.PrintLog("info", fmt.Sprintf("pod '%v' in namespace '%v' doesn't exist (it may have been already terminated)", pod, namespace))
		return
	}
	utils.PrintLog("info", fmt.Sprintf("MATCH: '%v' ACTION: '%v' POD: '%v' NAMESPACE: '%v'", rule.Name, rule.Action.Name, pod, namespace))
	var err error
	switch rule.Action.Name {
	case terminateStr:
		err = client.Terminate(pod, namespace, rule.Action.Options)
	case "label":
		err = client.Label(pod, namespace, rule.Action.Labels)
	}
	if err != nil {
		utils.PrintLog("error", fmt.Sprintf("ACTION: '%v' POD: '%v' NAMESPACE: '%v' ACTION: '%v' STATUS: 'Fail'", rule.Action.Name, rule.Name, pod, namespace))
		triggerNotification(rule.Name, rule.Action.Name, pod, namespace, "failure")
	} else {
		utils.PrintLog("info", fmt.Sprintf("ACTION: '%v' POD: '%v' NAMESPACE: '%v' STATUS: 'Success'", rule.Action.Name, pod, namespace))
		triggerNotification(rule.Name, rule.Action.Name, pod, namespace, "success")
	}
}

func triggerNotification(rule, action, pod, namespace, status string) {
	config := configuration.GetConfiguration()
	if config.Notifiers.Slack.WebhookURL != "" {
		notifier.SlackPost(rule, action, pod, namespace, status)
	}
}

// pingHandler is a simple handler to test if daemon is UP.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("pong\n"))
}

// healthHandler is a simple handler to test if daemon is UP.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status": "ok"}`))
}
