package log

import (
	"bytes"
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var Log = func(rule *rules.Rule, action *rules.Action, event *events.Event) (utils.LogLine, error) {
	pod := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"Pod":       pod,
		"Namespace": namespace,
	}

	parameters := action.GetParameters()
	tailLines := new(int64)
	if parameters["tail_lines"] != nil {
		*tailLines = int64(parameters["tail_lines"].(int))
	}
	if *tailLines == 0 {
		*tailLines = 20
	}

	command := new(string)
	if parameters["command"] != nil {
		*command = parameters["command"].(string)
	}

	client := kubernetes.GetClient()

	p, _ := client.GetPod(pod, namespace)
	containers := kubernetes.GetContainers(p)
	if len(containers) == 0 {
		err := fmt.Errorf("no container found")
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	ctx := context.Background()
	var output string

	for i, container := range containers {
		logs, err := client.Clientset.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{
			Container: container,
			TailLines: tailLines,
		}).Stream(ctx)
		if err != nil {
			if err != nil {
				if i == len(containers)-1 {
					return utils.LogLine{
						Objects: objects,
						Error:   err.Error(),
						Status:  "failure",
					}, err
				}
				continue
			}
		}
		defer logs.Close()

		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, logs)
		if err != nil {
			return utils.LogLine{
					Objects: objects,
					Status:  "failure",
					Error:   err.Error(),
				},
				err
		}

		output = buf.String()
		if output != "" {
			break
		}
	}

	return utils.LogLine{
			Objects: objects,
			Output:  output,
			Status:  "success",
		},
		nil
}

var CheckParameters = func(action *rules.Action) error {
	parameters := action.GetParameters()
	err := utils.CheckParameters(parameters, "tail_lines", utils.IntStr, nil, false)
	if err != nil {
		return err
	}

	return nil
}
