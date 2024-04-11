package terminate

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Falco-Talon/falco-talon/internal/events"
	kubernetes "github.com/Falco-Talon/falco-talon/internal/kubernetes/client"
	"github.com/Falco-Talon/falco-talon/internal/rules"
	"github.com/Falco-Talon/falco-talon/utils"
	"github.com/go-playground/validator/v10"
)

const validatorName = "is_absolut_or_percent"

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

	if parameters["ignore_daemonsets"] != nil || parameters["ignore_statefulsets"] != nil || parameters["min_healthy_replicas"] != nil {
		pod, err := client.GetPod(podName, namespace)
		if err != nil {
			return utils.LogLine{
					Objects: objects,
					Error:   err.Error(),
					Status:  "failure",
				},
				err
		}

		if len(pod.OwnerReferences) != 0 {
			switch pod.OwnerReferences[0].Kind {
			case "DaemonSet":
				if parameters["ignore_daemonsets"].(bool) {
					return utils.LogLine{
							Objects: objects,
							Result:  fmt.Sprintf("the pod %v in the namespace %v belongs to a Daemonset and ignore_daemonsets is true", podName, namespace),
							Status:  "ignored",
						},
						nil
				}
			case "StatefulSet":
				if parameters["ignore_statefulsets"].(bool) {
					return utils.LogLine{
							Objects: objects,
							Result:  fmt.Sprintf("the pod %v in the namespace %v belongs to a Statefulset and ignore_statefulsets is true", podName, namespace),
							Status:  "ignored",
						},
						nil
				}
			case "ReplicaSet":
				if parameters["min_healthy_replicas"] != nil {
					u, errG := client.GetReplicasetFromPod(pod)
					if errG != nil {
						return utils.LogLine{
								Objects: objects,
								Error:   errG.Error(),
								Status:  "failure",
							},
							errG
					}
					if u == nil {
						return utils.LogLine{
								Objects: objects,
								Error:   fmt.Sprintf("can't find the replicaset for the pod %v in namespace %v", podName, namespace),
								Status:  "failure",
							},
							fmt.Errorf("can't find the replicaset for the pod %v in namespace %v", podName, namespace)
					}
					if strings.Contains(fmt.Sprintf("%v", parameters["min_healthy_replicas"]), "%") {
						v, _ := strconv.ParseInt(strings.Split(parameters["min_healthy_replicas"].(string), "%")[0], 10, 64)
						if v > int64(100*u.Status.ReadyReplicas/u.Status.Replicas) {
							return utils.LogLine{
									Objects: objects,
									Result:  fmt.Sprintf("not enough healthy pods in the replicaset of the pod %v in namespace %v", podName, namespace),
									Status:  "ignored",
								},
								fmt.Errorf("not enough healthy pods in the replicaset of the pod %v in namespace %v", podName, namespace)
						}
					} else {
						v, _ := strconv.ParseInt(parameters["min_healthy_replicas"].(string), 10, 64)
						if v > int64(u.Status.ReadyReplicas) {
							return utils.LogLine{
									Objects: objects,
									Result:  fmt.Sprintf("not enough healthy pods in the replicaset of the pod %v in namespace %v", podName, namespace),
									Status:  "ignored",
								},
								fmt.Errorf("not enough healthy pods in the replicaset of the pod %v in namespace %v", podName, namespace)
						}
					}
				}
			}
		}
	}

	err := client.Clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds})
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

type Config struct {
	GracePeriodSeconds int    `mapstructure:"grace_period_seconds" validate:"omitempty"`
	IgnoreDaemonsets   bool   `mapstructure:"ignore_daemonsets" validate:"omitempty"`
	IgnoreStatefulSets bool   `mapstructure:"ignore_statefulsets" validate:"omitempty"`
	MinHealthyReplicas string `mapstructure:"min_healthy_replicas" validate:"omitempty,is_absolut_or_percent"`
}
