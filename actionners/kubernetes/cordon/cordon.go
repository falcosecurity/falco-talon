package cordon

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	jsonPatch = `[{"op": "replace", "path": "/spec/unschedulable", "value": true}]`
)

func Action(_ *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{}

	client := kubernetes.GetClient()

	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	node, err := client.GetNodeFromPod(pod)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	objects["node"] = node.Name

	_, err = client.Clientset.CoreV1().Nodes().Patch(context.Background(), node.Name, types.JSONPatchType, []byte(jsonPatch), metav1.PatchOptions{})
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the node '%v' has been cordoned", node.Name),
		Status:  "success",
	}, nil, nil
}
