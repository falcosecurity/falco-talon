package script

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var Script = func(rule *rules.Rule, event *events.Event) (utils.LogLine, error) {
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
	script := new(string)
	if parameters["script"] != nil {
		*script = parameters["script"].(string)
	}

	reader := strings.NewReader(*script)

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
	var container string

	// copy the script to /tmp of the pod
	for i, j := range containers {
		container = j
		request := client.CoreV1().RESTClient().
			Post().
			Namespace(namespace).
			Resource("pods").
			Name(pod).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: container,
				Command:   []string{"tee", "/tmp/talon-script.sh", ">", "/dev/null"},
				Stdin:     true,
				Stdout:    false,
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
		Stdin:  reader,
		Stdout: nil,
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

	// run the script
	request := client.CoreV1().RESTClient().
		Post().
		Namespace(namespace).
		Resource("pods").
		Name(pod).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   []string{*shell, "/tmp/talon-script.sh"},
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)
	exec, err = remotecommand.NewSPDYExecutor(client.RestConfig, "POST", request.URL())
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, err
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

var CheckParameters = func(rule *rules.Rule) error {
	parameters := rule.GetParameters()
	var err error
	err = utils.CheckParameters(parameters, "shell", utils.StringStr, nil, false)
	if err != nil {
		return err
	}
	err = utils.CheckParameters(parameters, "script", utils.StringStr, nil, true)
	if err != nil {
		return err
	}
	return nil
}
