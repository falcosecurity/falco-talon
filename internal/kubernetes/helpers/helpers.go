package helpers

import (
	"fmt"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/utils"
	corev1 "k8s.io/api/core/v1"
	"strconv"
	"strings"
)

func LogIgnoredPods(parameters map[string]interface{}, client *kubernetes.Client, pod corev1.Pod, objects map[string]string) (utils.LogLine, error, bool) {
	if parameters["ignore_daemonsets"] != nil || parameters["ignore_statefulsets"] != nil || parameters["min_healthy_replicas"] != nil {
		if len(pod.OwnerReferences) != 0 {
			switch pod.OwnerReferences[0].Kind {
			case "DaemonSet":
				if parameters["ignore_daemonsets"].(bool) {
					return utils.LogLine{
						Objects: objects,
						Result:  fmt.Sprintf("the pod %v in the namespace %v belongs to a Daemonset and ignore_daemonsets is true", pod.Name, pod.Namespace),
						Status:  "ignored",
					}, nil, true
				}
			case "StatefulSet":
				if parameters["ignore_statefulsets"].(bool) {
					return utils.LogLine{
						Objects: objects,
						Result:  fmt.Sprintf("the pod %v in the namespace %v belongs to a Statefulset and ignore_statefulsets is true", pod.Name, pod.Namespace),
						Status:  "ignored",
					}, nil, true
				}
			case "ReplicaSet":
				if parameters["min_healthy_replicas"] != nil {
					u, err := client.GetReplicasetFromPod(&pod)
					if err != nil {
						return utils.LogLine{
							Objects: objects,
							Error:   err.Error(),
							Status:  "failure",
						}, fmt.Errorf("error while getting the replicaset for the pod %v in namespace %v", pod.Name, pod.Namespace), false
					}
					if u == nil {
						return utils.LogLine{
							Objects: objects,
							Error:   fmt.Sprintf("can't find the replicaset for the pod %v in namespace %v", pod.Name, pod.Namespace),
							Status:  "failure",
						}, fmt.Errorf("can't find the replicaset for the pod %v in namespace %v", pod.Name, pod.Namespace), false
					}
					if strings.Contains(fmt.Sprintf("%v", parameters["min_healthy_replicas"]), "%") {
						v, _ := strconv.ParseInt(strings.Split(parameters["min_healthy_replicas"].(string), "%")[0], 10, 64)
						if v > int64(100*u.Status.ReadyReplicas/u.Status.Replicas) {
							return utils.LogLine{
								Objects: objects,
								Result:  fmt.Sprintf("not enough healthy pods in the replicaset of the pod %v in namespace %v", pod.Name, pod.Namespace),
								Status:  "ignored",
							}, fmt.Errorf("not enough healthy pods in the replicaset of the pod %v in namespace %v", pod.Name, pod.Namespace), true
						}
					} else {
						v, _ := strconv.ParseInt(parameters["min_healthy_replicas"].(string), 10, 64)
						if v > int64(u.Status.ReadyReplicas) {
							return utils.LogLine{
								Objects: objects,
								Result:  fmt.Sprintf("not enough healthy pods in the replicaset of the pod %v in namespace %v", pod.Name, pod.Namespace),
								Status:  "ignored",
							}, fmt.Errorf("not enough healthy pods in the replicaset of the pod %v in namespace %v", pod.Name, pod.Namespace), true
						}
					}
				}
			}
		}
	}
	return utils.LogLine{}, nil, false
}
