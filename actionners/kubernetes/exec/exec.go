package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var Exec = func(rule *rules.Rule, action *rules.Action, event *events.Event) (utils.LogLine, error) {
	pod := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"Pod":       pod,
		"Namespace": namespace,
	}

	parameters := action.GetParameters()
	shell := new(string)
	if parameters["shell"] != nil {
		*shell = parameters["shell"].(string)
	}
	if *shell == "" {
		*shell = "/bin/sh"
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

	var err error
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	var exec remotecommand.Executor
	for i, container := range containers {
		request := client.CoreV1().RESTClient().
			Post().
			Namespace(namespace).
			Resource("pods").
			Name(pod).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: container,
				Command:   []string{*shell, "-c", *command},
				Stdin:     false,
				Stdout:    true,
				Stderr:    true,
				TTY:       false,
			}, scheme.ParameterCodec)
		exec, err = remotecommand.NewSPDYExecutor(client.RestConfig, "POST", request.URL())
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
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: buf,
		Stderr: errBuf,
		Tty:    false,
	})
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   errBuf.String(),
				Status:  "failure",
			},
			err
	}

	output := utils.RemoveAnsiCharacters(buf.String())

	return utils.LogLine{
			Objects: objects,
			Output:  output,
			Status:  "success",
		},
		nil
}

var CheckParameters = func(action *rules.Action) error {
	parameters := action.GetParameters()
	var err error
	err = utils.CheckParameters(parameters, "shell", utils.StringStr, nil, false)
	if err != nil {
		return err
	}
	if parameters["command"] == nil {
		return errors.New("missing parameter 'command'")
	}
	err = utils.CheckParameters(parameters, "command", utils.StringStr, nil, true)
	if err != nil {
		return err
	}
	return nil
}
