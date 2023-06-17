package script

import (
	"bytes"
	"context"
	"encoding/base64"

	v1 "k8s.io/api/core/v1"
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

	if *script != "" {
		*script = base64.StdEncoding.EncodeToString([]byte(*script))
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
			Command: []string{
				*shell,
				"-c",
				"echo",
				"'" + *script + "'",
				// ">",
				// "/tmp/falco-talon.b64.sh",
				// "'",
				// "cat /tmp/falco-talon.b64.sh | base64 -d > /tmp/falco-talon.sh;",
				// "chmod +x /tmp/falco-talon.b64.sh;",
				// "/tmp/falco-talon.sh",
				// *shell,
				// "-c",
			},
			Stdin:  false,
			Stdout: true,
			Stderr: true,
			TTY:    true,
		}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(client.RestConfig, "POST", request.URL())
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
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
			Objects: map[string]string{
				"Pod":       pod,
				"Namespace": namespace,
			},
			Output: output,
			Status: "success",
		},
		nil
}

var CheckParameters = func(rule *rules.Rule) error {
	parameters := rule.GetParameters()
	var err error
	err = utils.CheckParameters(parameters, "shell", utils.StringStr, false)
	if err != nil {
		return err
	}
	err = utils.CheckParameters(parameters, "script", utils.StringStr, true)
	if err != nil {
		return err
	}
	return nil
}
