package exec

import (
	"bytes"
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var Exec = func(rule *rules.Rule, event *events.Event) (utils.LogLine, error) {
	pod := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"Pod":       pod,
		"Namespace": namespace,
	}

	parameters := rule.GetParameters()
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

	var err error
	var container string
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	var exec remotecommand.Executor
	for i, j := range containers {
		container = j
		request := client.CoreV1().RESTClient().
			Post().
			Namespace(namespace).
			Resource("pods").
			Name(pod).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: j,
				Command:   []string{*shell, "-c", *command},
				Stdin:     false,
				Stdout:    true,
				Stderr:    true,
				TTY:       true,
			}, scheme.ParameterCodec)
		exec, err = remotecommand.NewSPDYExecutor(client.RestConfig, "POST", request.URL())
		if err != nil {
			if i == len(container)-1 {
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
		Stdout: buf,
		Stderr: errBuf,
	})
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
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

var CheckParameters = func(rule *rules.Rule) error {
	parameters := rule.GetParameters()
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
