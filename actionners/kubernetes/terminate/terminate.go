package terminate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var Terminate = func(rule *rules.Rule, event *events.Event) (utils.LogLine, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"Pod":       podName,
		"Namespace": namespace,
	}

	parameters := rule.GetParameters()
	gracePeriodSeconds := new(int64)
	if parameters["gracePeriodSeconds"] != nil {
		*gracePeriodSeconds = int64(parameters["gracePeriodSeconds"].(int))
	}

	client := kubernetes.GetClient()

	if parameters["ignoreDaemonsets"] != nil || parameters["ignoreStatefulsets"] != nil || parameters["minHealthyReplicas"] != nil {
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
				if parameters["ignoreDaemonsets"].(bool) {
					return utils.LogLine{
							Objects: objects,
							Result:  fmt.Sprintf("the pod %v in the namespace %v belongs to a Daemonset and ignoreDaemonsets is true", podName, namespace),
							Status:  "ignored",
						},
						nil
				}
			case "StatefulSet":
				if parameters["ignoreStatefulsets"].(bool) {
					return utils.LogLine{
							Objects: objects,
							Result:  fmt.Sprintf("the pod %v in the namespace %v belongs to a Statefulset and ignoreStatefulsets is true", podName, namespace),
							Status:  "ignored",
						},
						nil
				}
			case "ReplicaSet":
				if parameters["minHealthyReplicas"] != nil {
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
					if strings.Contains(fmt.Sprintf("%v", parameters["minHealthyReplicas"]), "%") {
						v, _ := strconv.ParseInt(strings.Split(parameters["minHealthyReplicas"].(string), "%")[0], 10, 64)
						if v > int64(100*u.Status.ReadyReplicas/u.Status.Replicas) {
							return utils.LogLine{
									Objects: objects,
									Result:  fmt.Sprintf("not enough healthy pods in the replicaset of the pod %v in namespace %v", podName, namespace),
									Status:  "ignored",
								},
								fmt.Errorf("not enough healthy pods in the replicaset of the pod %v in namespace %v", podName, namespace)
						}
					} else {
						v, _ := strconv.ParseInt(parameters["minHealthyReplicas"].(string), 10, 64)
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

	// err := client.Clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds})
	// if err != nil {
	// 	return utils.LogLine{
	// 			Objects: objects,
	// 			Status:  "failure",
	// 			Error:   err.Error(),
	// 		},
	// 		err
	// }
	return utils.LogLine{
			Objects: objects,
			Status:  "success",
		},
		nil
}

var CheckParameters = func(rule *rules.Rule) error {
	parameters := rule.GetParameters()
	err := utils.CheckParameters(parameters, "gracePeriodSeconds", utils.IntStr, nil, false)
	if err != nil {
		return err
	}
	err = utils.CheckParameters(parameters, "ignoreDaemonsets", utils.BoolStr, nil, false)
	if err != nil {
		return err
	}
	err = utils.CheckParameters(parameters, "ignoreStatefulsets", utils.BoolStr, nil, false)
	if err != nil {
		return err
	}
	reg := regexp.MustCompile(`\d+(%)?`)
	err = utils.CheckParameters(parameters, "minHealthyReplicas", utils.StringStr, reg, false)
	if err != nil {
		return err
	}
	return nil
}
