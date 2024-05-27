package terminate

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	helpers "github.com/falco-talon/falco-talon/actionners/kubernetes/helpers"
	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

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

	ownerKind, err := kubernetes.GetOwnerKind(*pod)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	switch ownerKind {
	case "DaemonSet":
		if ignoreDaemonsets, ok := parameters["ignore_daemonsets"].(bool); ok && ignoreDaemonsets {
			return utils.LogLine{
				Objects: objects,
				Status:  "ignored",
				Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a DaemonSet and will be ignored.", podName, namespace),
			}, nil
		}
	case "StatefulSet":
		if ignoreStatefulsets, ok := parameters["ignore_statefulsets"].(bool); ok && ignoreStatefulsets {
			return utils.LogLine{
				Objects: objects,
				Status:  "ignored",
				Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a StatefulSet and will be ignored.", podName, namespace),
			}, nil
		}
	case "ReplicaSet":
		replicaSetName, err2 := kubernetes.GetOwnerName(*pod)
		if err2 != nil {
			return utils.LogLine{
				Objects: objects,
				Status:  "failure",
				Error:   err2.Error(),
			}, nil
		}
		if minHealthyReplicas, ok := parameters["min_healthy_replicas"].(string); ok && minHealthyReplicas != "" {
			replicaSet, err2 := client.GetReplicaSet(replicaSetName, pod.Namespace)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Status:  "failure",
					Error:   err2.Error(),
				}, nil
			}
			minHealthyReplicasValue, kind, err2 := helpers.ParseMinHealthyReplicas(minHealthyReplicas)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Status:  "failure",
					Error:   err2.Error(),
				}, nil
			}
			switch kind {
			case "absolut":
				healthyReplicasCount, err2 := kubernetes.GetHealthyReplicasCount(replicaSet)
				if err2 != nil {
					return utils.LogLine{
						Objects: objects,
						Status:  "failure",
						Error:   err2.Error(),
					}, nil
				}
				if healthyReplicasCount < minHealthyReplicasValue {
					return utils.LogLine{
						Objects: objects,
						Status:  "ignored",
						Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a ReplicaSet without enough healthy replicas and will be ignored.", podName, namespace),
					}, nil
				}
			case "percent":
				healthyReplicasPercent, err2 := kubernetes.GetHealthyReplicasCount(replicaSet)
				if err2 != nil {
					return utils.LogLine{
						Objects: objects,
						Status:  "failure",
						Error:   err2.Error(),
					}, nil
				}
				if healthyReplicasPercent < minHealthyReplicasValue {
					return utils.LogLine{
						Objects: objects,
						Status:  "ignored",
						Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a ReplicaSet without enough healthy replicas and will be ignored.", podName, namespace),
					}, nil
				}
			}
		}
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

	err = utils.AddCustomValidation(helpers.ValidatorMinHealthyReplicas, helpers.ValidateMinHealthyReplicas)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(config)
	if err != nil {
		return err
	}

	return nil
}
