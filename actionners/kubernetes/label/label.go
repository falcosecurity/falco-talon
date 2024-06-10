package label

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type patch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value,omitempty"`
}

type Config struct {
	Labels map[string]string `mapstructure:"labels" validate:"required"`
	Level  string            `mapstructure:"level" validate:"omitempty"`
}

const (
	metadataLabels = "/metadata/labels/"
	podStr         = "pod"
	nodeStr        = "node"
)

func Action(action *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{}

	payload := make([]patch, 0)
	parameters := action.GetParameters()
	var config Config
	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	client := kubernetes.GetClient()

	var kind string
	var node *corev1.Node

	if config.Level == nodeStr {
		kind = nodeStr
		pod, err2 := client.GetPod(podName, namespace)
		if err2 != nil {
			return utils.LogLine{
				Objects: objects,
				Error:   err2.Error(),
				Status:  "failure",
			}, nil, err2
		}
		node, err = client.GetNodeFromPod(pod)
		if err != nil {
			return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			}, nil, err
		}
		objects[nodeStr] = node.Name
	} else {
		kind = podStr
		objects[podStr] = podName
		objects["namespace"] = namespace
	}

	for i, j := range config.Labels {
		if fmt.Sprintf("%v", j) == "" {
			continue
		}
		payload = append(payload, patch{
			Op:    "replace",
			Path:  metadataLabels + i,
			Value: fmt.Sprintf("%v", j),
		})
	}

	payloadBytes, _ := json.Marshal(payload)
	if kind == podStr {
		_, err = client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), podName, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	}
	if kind == nodeStr {
		_, err = client.Clientset.CoreV1().Nodes().Patch(context.Background(), node.Name, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	}
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	payload = make([]patch, 0)
	action.GetParameters()
	for i, j := range config.Labels {
		if fmt.Sprintf("%v", j) != "" {
			continue
		}
		payload = append(payload, patch{
			Op:   "remove",
			Path: metadataLabels + i,
		})
	}

	payloadBytes, _ = json.Marshal(payload)
	if kind == nodeStr {
		_, err = client.Clientset.CoreV1().Nodes().Patch(context.Background(), node.Name, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	} else {
		_, err = client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), podName, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	}
	if err != nil {
		if err.Error() != "the server rejected our request due to an error in our request" {
			return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			}, nil, err
		}
	}
	var output string
	if kind == nodeStr {
		output = fmt.Sprintf("the node '%v' has been labeled", node.Name)
	} else {
		output = fmt.Sprintf("the pod '%v' in the namespace '%v' has been labeled", podName, namespace)
	}
	return utils.LogLine{
		Objects: objects,
		Output:  output,
		Status:  "success",
	}, nil, nil
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
		return errors.New("parameter 'labels' should have at least one label")
	}
	return nil
}
