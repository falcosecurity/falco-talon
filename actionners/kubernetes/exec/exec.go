package exec

import (
	"bytes"
	"context"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"
)

var Exec = func(rule *rules.Rule, event *events.Event) (utils.LogLine, error) {
	pod := event.GetPodName()
	namespace := event.GetNamespaceName()

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

	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	request := client.CoreV1().RESTClient().
		Post().
		Namespace(namespace).
		Resource("pods").
		Name(pod).
		SubResource("exec").
		VersionedParams(&v1.PodExecOptions{
			Command: []string{*shell, "-c", *command},
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     true,
		}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(client.RestConfig, "POST", request.URL())
	if err != nil {
		return utils.LogLine{
				Pod:       pod,
				Namespace: namespace,
				Error:     err,
				Status:    "failure",
			},
			err
	}
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdout: buf,
		Stderr: errBuf,
	})
	if err != nil {
		return utils.LogLine{
				Pod:       pod,
				Namespace: namespace,
				Error:     err,
				Status:    "failure",
			},
			err
	}

	return utils.LogLine{
			Pod:       pod,
			Namespace: namespace,
			Output:    buf.String(),
			Status:    "success",
		},
		nil
}

var CheckParameters = func(rule *rules.Rule) error {
	parameters := rule.GetParameters()
	if err := utils.CheckParameters(parameters, "shell", utils.StringStr); err != nil {
		return err
	}
	if err := utils.CheckParameters(parameters, "command", utils.StringStr); err != nil {
		return err
	}
	return nil
}
