package labelize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

type patch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value,omitempty"`
}

type Config struct {
	Labels map[string]string `mapstructure:"labels" validate:"required,omitempty"`
}

const (
	metadataLabels = "/metadata/labels/"
)

func Action(action *rules.Action, event *events.Event) (utils.LogLine, error) {
	pod := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"pod":       pod,
		"namespace": namespace,
	}

	payload := make([]patch, 0)
	parameters := action.GetParameters()
	for i, j := range parameters["labels"].(map[string]interface{}) {
		if fmt.Sprintf("%v", j) == "" {
			continue
		}
		payload = append(payload, patch{
			Op:    "replace",
			Path:  metadataLabels + i,
			Value: fmt.Sprintf("%v", j),
		})
	}

	client := kubernetes.GetClient()

	payloadBytes, _ := json.Marshal(payload)
	_, err := client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), pod, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	payload = make([]patch, 0)
	action.GetParameters()
	for i, j := range parameters["labels"].(map[string]interface{}) {
		if fmt.Sprintf("%v", j) != "" {
			continue
		}
		payload = append(payload, patch{
			Op:   "remove",
			Path: metadataLabels + i,
		})
	}

	payloadBytes, _ = json.Marshal(payload)
	_, err = client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), pod, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	if err != nil {
		if err.Error() != "the server rejected our request due to an error in our request" {
			return utils.LogLine{
					Objects: objects,
					Error:   err.Error(),
					Status:  "failure",
				},
				err
		}
	}
	return utils.LogLine{
			Objects: objects,
			Output:  fmt.Sprintf("the pod '%v' in the namespace '%v' has been labelized", pod, namespace),
			Status:  "success",
		},
		nil
}

func CheckParameters(action *rules.Action) error {
	parameters := action.GetParameters()

	var config Config

	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(config)
	if err != nil {
		return err
	}

	if len(config.Labels) == 0 {
		return errors.New("parameter 'labels' sould have at least one label.")
	}
	return nil
}
