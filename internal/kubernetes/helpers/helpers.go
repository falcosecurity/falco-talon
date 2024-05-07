package helpers

import (
	"fmt"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/utils"
	corev1 "k8s.io/api/core/v1"
	"reflect"
	"strconv"
	"strings"
)

func GetOwnerKind(pod corev1.Pod) (string, error) {
	if len(pod.OwnerReferences) == 0 {
		return "", fmt.Errorf("no owner references found")
	}
	return pod.OwnerReferences[0].Kind, nil
}

func GetOwnerName(pod corev1.Pod) (string, error) {
	if len(pod.OwnerReferences) == 0 {
		return "", fmt.Errorf("no owner references found")
	}
	return pod.OwnerReferences[0].Name, nil
}

func VerifyIfPodWillBeIgnored(parameters map[string]interface{}, client *kubernetes.Client, pod corev1.Pod, objects map[string]string) (utils.LogLine, error, bool) {
	kind, err := GetOwnerKind(pod)
	if err != nil {
		return utils.LogLine{}, err, false
	}

	var result, status string
	var ignore bool

	// Safe type assertion with check for existence
	switch kind {
	case "DaemonSet":
		if ignoreDaemonsets, ok := parameters["ignore_daemonsets"].(bool); ok && ignoreDaemonsets {
			result = fmt.Sprintf("The pod %v in namespace %v belongs to a DaemonSet and will be ignored.", pod.Name, pod.Namespace)
			status = "ignored"
			ignore = true
		}
	case "StatefulSet":
		if ignoreStatefulsets, ok := parameters["ignore_statefulsets"].(bool); ok && ignoreStatefulsets {
			result = fmt.Sprintf("The pod %v in namespace %v belongs to a StatefulSet and will be ignored.", pod.Name, pod.Namespace)
			status = "ignored"
			ignore = true
		}
	case "ReplicaSet":
		return checkReplicaSet(parameters, client, pod, objects)
	}

	if result == "" {
		return utils.LogLine{}, nil, false
	}

	return utils.LogLine{
		Objects: objects,
		Result:  result,
		Status:  status,
	}, nil, ignore
}

func checkReplicaSet(parameters map[string]interface{}, client *kubernetes.Client, pod corev1.Pod, objects map[string]string) (utils.LogLine, error, bool) {
	// Safely assert the existence and type of "min_healthy_replicas"
	minHealthyParam, ok := parameters["min_healthy_replicas"]
	if !ok {
		return utils.LogLine{}, nil, false // Early return if parameter does not exist
	}

	minHealthy, err := parseMinHealthyReplicas(minHealthyParam)
	if err != nil {
		return utils.LogLine{}, err, false // Return error if parsing fails
	}

	replicaset, err := client.GetReplicasetFromPod(&pod)
	if err != nil {
		return utils.LogLine{}, err, false // Return error if unable to get ReplicaSet
	}

	healthyReplicas := int64(replicaset.Status.ReadyReplicas)
	if minHealthy > healthyReplicas {
		return utils.LogLine{
			Objects: objects,
			Result:  fmt.Sprintf("Not enough healthy pods: %v required, %v available in ReplicaSet of pod %v in namespace %v.", minHealthy, healthyReplicas, pod.Name, pod.Namespace),
			Status:  "ignored",
		}, nil, true // Indicate that the ReplicaSet is ignored due to not meeting the health criteria
	}

	return utils.LogLine{}, nil, false // Return default case with no errors and not ignored
}

func parseMinHealthyReplicas(value interface{}) (int64, error) {
	switch v := value.(type) {
	case string:
		if strings.HasSuffix(v, "%") {
			percentage, err := strconv.ParseInt(strings.TrimSuffix(v, "%"), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid percentage format: %v", err)
			}
			return percentage, nil
		}
		return strconv.ParseInt(v, 10, 64)
	case int, int64:
		return reflect.ValueOf(v).Int(), nil
	default:
		return 0, fmt.Errorf("invalid type for min_healthy_replicas")
	}
}
