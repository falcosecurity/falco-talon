package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
)

type patch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value,omitempty"`
}

var Labelize = func(rule *rules.Rule, event *events.Event) error {
	pod := event.GetPod()
	namespace := event.GetNamespace()

	payload := make([]patch, 0)
	for i, j := range rule.GetArguments() {
		if j == "" {
			continue
		}
		payload = append(payload, patch{
			Op:    "replace",
			Path:  "/metadata/labels/" + i,
			Value: fmt.Sprintf("%v", j),
		})
	}

	payloadBytes, _ := json.Marshal(payload)
	_, err := client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), pod, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	if err != nil {
		return err
	}

	payload = make([]patch, 0)
	for i, j := range rule.GetArguments() {
		if j != "" {
			continue
		}
		payload = append(payload, patch{
			Op:   "remove",
			Path: "/metadata/labels/" + i,
		})
	}

	payloadBytes, _ = json.Marshal(payload)
	_, err = client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), pod, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	if err != nil {
		if err.Error() != "the server rejected our request due to an error in our request" {
			return err
		}
	}
	return nil
}
