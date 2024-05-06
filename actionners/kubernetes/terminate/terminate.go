package terminate

import (
	"context"
	"fmt"
	"github.com/falco-talon/falco-talon/internal/kubernetes/helpers"
	"github.com/go-playground/validator/v10"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"regexp"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

const validatorName = "is_absolut_or_percent"

type Config struct {
	MinHealthyReplicas string `mapstructure:"min_healthy_replicas" validate:"omitempty,is_absolut_or_percent"`
	IgnoreDaemonsets   bool   `mapstructure:"ignore_daemonsets" validate:"omitempty"`
	IgnoreStatefulSets bool   `mapstructure:"ignore_statefulsets" validate:"omitempty"`
	GracePeriodSeconds int    `mapstructure:"grace_period_seconds" validate:"omitempty"`
}

func Action(action *rules.Action, event *events.Event) (utils.LogLine, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"pod":       podName,
		"namespace": namespace,
	}

	parameters := action.GetParameters()
	gracePeriodSeconds := new(int64)
	if parameters["grace_period_seconds"] != nil {
		*gracePeriodSeconds = int64(parameters["grace_period_seconds"].(int))
	}

	client := kubernetes.GetClient()
	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	line, err, ignored := helpers.LogIgnoredPods(parameters, client, *pod, objects)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Status:  "failure",
			Error:   err.Error(),
		}, err
	}
	if ignored {
		return line, nil
	}

	err = client.Clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds})
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Status:  "failure",
				Error:   err.Error(),
			},
			err
	}
	return utils.LogLine{
			Objects: objects,
			Output:  fmt.Sprintf("the pod '%v' in the namespace '%v' has been terminated", podName, namespace),
			Status:  "success",
		},
		nil
}

func CheckParameters(action *rules.Action) error {
	parameters := action.GetParameters()

	var config Config
	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return err
	}

	err = utils.AddCustomValidation(validatorName, ValidateMinHealthyReplicas)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(config)
	if err != nil {
		return err
	}

	return nil
}

func ValidateMinHealthyReplicas(fl validator.FieldLevel) bool {
	minHealthyReplicas := fl.Field().String()

	reg := regexp.MustCompile(`\d+(%)?`)
	result := reg.MatchString(minHealthyReplicas)
	return result
}
