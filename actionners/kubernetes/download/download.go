package copy

import (
	"bytes"
	"fmt"
	"os"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	File string `mapstructure:"file" validate:"required"`
}

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
			Status:  utils.FailureStr,
		}, nil, err
	}

	file := new(string)
	*file = config.File

	event.ExportEnvVars()
	*file = os.ExpandEnv(*file)

	objects["file"] = *file

	client := kubernetes.GetClient()

	p, _ := client.GetPod(pod, namespace)
	containers := kubernetes.GetContainers(p)
	if len(containers) == 0 {
		err = fmt.Errorf("no container found")
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	output := new(bytes.Buffer)
	for i, container := range containers {
		command := []string{"cat", *file}
		output, err = client.Exec(namespace, pod, container, command, "")
		if err != nil {
			if i == len(containers)-1 {
				return utils.LogLine{
					Objects: objects,
					Error:   err.Error(),
					Status:  utils.FailureStr,
				}, nil, err
			}
			continue
		}
		break
	}
	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the file '%v' has been downloaded", *file),
		Status:  utils.SuccessStr,
	}, &model.Data{Name: *file, Namespace: event.GetNamespaceName(), Pod: event.GetPodName(), Hostname: event.GetHostname(), Bytes: output.Bytes()}, nil
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
