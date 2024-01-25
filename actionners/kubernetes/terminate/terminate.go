package terminate

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var Terminate = func(rule *rules.Rule, action *rules.Action, event *events.Event) (utils.LogLine, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"Pod":       podName,
		"Namespace": namespace,
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

var CheckParameters = func(action *rules.Action) error {
	parameters := action.GetParameters()
	err := utils.CheckParameters(parameters, "grace_period_seconds", utils.IntStr, nil, false)
	if err != nil {
		return err
	}
	err = utils.CheckParameters(parameters, "ignore_daemonsets", utils.BoolStr, nil, false)
	if err != nil {
		return err
	}
	err = utils.CheckParameters(parameters, "ignore_statefulsets", utils.BoolStr, nil, false)
	if err != nil {
		return err
	}
	reg := regexp.MustCompile(`\d+(%)?`)
	err = utils.CheckParameters(parameters, "min_healthy_replicas", utils.StringStr, reg, false)
	if err != nil {
		return err
	}
	return nil
}
