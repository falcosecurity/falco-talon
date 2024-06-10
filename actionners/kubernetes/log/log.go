package log

import (
	"bytes"
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	TailLines int `mapstructure:"tail_lines" validate:"gte=0,omitempty"`
}

const (
	defaultTailLines int = 20
)

func Action(action *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error) {
	pod := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"pod":       pod,
		"namespace": namespace,
	}

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

	tailLines := new(int64)
	*tailLines = int64(defaultTailLines)
	if config.TailLines > 0 {
		*tailLines = int64(config.TailLines)
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
		}, nil, err
	}

	ctx := context.Background()
	var output []byte

	for i, container := range containers {
		logs, err := client.Clientset.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{
			Container: container,
			TailLines: tailLines,
		}).Stream(ctx)
		if err != nil {
			if i == len(containers)-1 {
				return utils.LogLine{
					Objects: objects,
					Error:   err.Error(),
					Status:  "failure",
				}, nil, err
			}
			continue
		}
		defer logs.Close()

		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, logs)
		if err != nil {
			return utils.LogLine{
				Objects: objects,
				Status:  "failure",
				Error:   err.Error(),
			}, nil, err
		}

		output = buf.Bytes()
		if len(output) != 0 {
			break
		}
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the logs for the pod '%v' in the namespace '%v' has been downloaded", pod, namespace),
		Status:  "success",
	}, &model.Data{Name: "log", Namespace: namespace, Pod: pod, Hostname: event.GetHostname(), Bytes: output}, nil
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

	return nil
}
