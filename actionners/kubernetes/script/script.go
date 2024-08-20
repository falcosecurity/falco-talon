package script

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	Script string `mapstructure:"script" validate:"omitempty"`
	File   string `mapstructure:"file" validate:"omitempty"`
	Shell  string `mapstructure:"shell" validate:"omitempty"`
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

	shell := new(string)
	if config.Shell != "" {
		*shell = config.Shell
	} else {
		*shell = "/bin/sh"
	}

	script := new(string)
	if config.Script != "" {
		*script = config.Script
	}

	if config.File != "" {
		fileContent, err2 := os.ReadFile(config.File)
		if err2 != nil {
			return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				},
				nil,
				err2
		}
		*script = string(fileContent)
	}

	event.ExportEnvVars()
	*script = os.ExpandEnv(*script)

	client := kubernetes.GetClient()

	p, _ := client.GetPod(pod, namespace)
	containers := kubernetes.GetContainers(p)
	if len(containers) == 0 {
		err = fmt.Errorf("no container found")
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}

	// copy the script to /tmp of the pod
	var container string
	output := new(bytes.Buffer)
	for i, j := range containers {
		container = j
		command := []string{"tee", "/tmp/talon-script.sh", ">", "/dev/null"}
		_, err = client.Exec(namespace, pod, container, command, *script)
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
	}

	// run the script
	command := []string{*shell, "/tmp/talon-script.sh"}
	output, err = client.Exec(namespace, pod, container, command, "")
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	return utils.LogLine{
			Objects: objects,
			Output:  utils.RemoveAnsiCharacters(output.String()),
			Status:  utils.SuccessStr,
		},
		nil,
		nil
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

	err = validateConfig(config)
	if err != nil {
		return err
	}
	return nil
}

func validateConfig(config Config) error {
	if config.Script == "" && config.File == "" {
		return errors.New("missing parameter 'script' or 'file'")
	}
	if config.Script != "" && config.File != "" {
		return errors.New("'script' and 'file' parameters can't be set at the same time")
	}
	if config.File != "" {
		_, err := os.Stat(config.File)
		if os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
