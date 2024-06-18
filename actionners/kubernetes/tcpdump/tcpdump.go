package tcpdump

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	Duration int `mapstructure:"duration" validate:"gte=0"`
	Snaplen  int `mapstructure:"snaplen" validate:"gte=0"`
}

const (
	baseName   string = "falco-talon-tcpdump-"
	defaultTTL int    = 300
)

func Action(action *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"pod":       podName,
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

	if config.Duration == 0 {
		config.Duration = 5
	}

	client := kubernetes.GetClient()

	pod, _ := client.GetPod(podName, namespace)
	containers := kubernetes.GetContainers(pod)
	if len(containers) == 0 {
		err = fmt.Errorf("no container found")
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	ephemeralContainerName := fmt.Sprintf("%v%v", baseName, uuid.NewString()[:5])

	err = client.CreateEphemeralContainer(pod, containers[0], ephemeralContainerName, defaultTTL)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	command := []string{"tee", "/tmp/talon-script.sh", ">", "/dev/null"}
	script := fmt.Sprintf("timeout %vs tcpdump -n -i any -s %v -w /tmp/tcpdump.pcap || [ $? -eq 124 ] && echo OK || exit 1", config.Duration, config.Snaplen)
	_, err = client.Exec(namespace, podName, ephemeralContainerName, command, script)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	command = []string{"sh", "/tmp/talon-script.sh"}
	_, err = client.Exec(namespace, podName, ephemeralContainerName, command, "")
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	command = []string{"cat", "/tmp/tcpdump.pcap"}
	output, err := client.Exec(namespace, podName, ephemeralContainerName, command, "")
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("a tcpdump '%v' has been created", "tcpdump.pcap"),
		Status:  "success",
	}, &model.Data{Name: "tcpdump.pcap", Namespace: event.GetNamespaceName(), Pod: event.GetPodName(), Hostname: event.GetHostname(), Bytes: output.Bytes()}, nil
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
