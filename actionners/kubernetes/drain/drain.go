package drain

import (
	"context"
	"fmt"
	"sync"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	helpers "github.com/falco-talon/falco-talon/actionners/kubernetes/helpers"
	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	// EvictionKind represents the kind of evictions object
	EvictionKind = "Eviction"
	// EvictionSubresource represents the kind of evictions object as pod's subresource
	EvictionSubresource = "pods/eviction"
)

type Config struct {
	MinHealthyReplicas string `mapstructure:"min_healthy_replicas" validate:"omitempty,is_absolut_or_percent"`
	IgnoreErrors       bool   `mapstructure:"ignore_errors" validate:"omitempty"`
	IgnoreDaemonsets   bool   `mapstructure:"ignore_daemonsets" validate:"omitempty"`
	IgnoreStatefulSets bool   `mapstructure:"ignore_statefulsets" validate:"omitempty"`
	GracePeriodSeconds int    `mapstructure:"grace_period_seconds" validate:"omitempty"`
}

func Action(action *rules.Action, event *events.Event) (utils.LogLine, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()
	objects := map[string]string{}

	parameters := action.GetParameters()
	gracePeriodSeconds := new(int64)
	if val, ok := parameters["grace_period_seconds"].(int); ok {
		*gracePeriodSeconds = int64(val)
	}

	client := kubernetes.GetClient()
	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, err
	}

	node, err := client.GetNodeFromPod(pod)
	if err != nil {
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, err
	}
	nodeName := node.GetName()
	objects["node"] = nodeName

	pods, err := client.Clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, err
	}

	var ignoredNodesCount, evictionErrorsCount, otherErrorsCount int

	var wg sync.WaitGroup

	for _, p := range pods.Items {
		wg.Add(1)
		defer wg.Done()
		go func() {
			var ignored bool

			ownerKind, err := kubernetes.GetOwnerKind(p)
			if err != nil {
				otherErrorsCount++
				return
			}

			switch ownerKind {
			case "DaemonSet":
				if ignoreDaemonsets, ok := parameters["ignore_daemonsets"].(bool); ok && ignoreDaemonsets {
					ignored = true
					ignoredNodesCount++
				}
			case "StatefulSet":
				if ignoreStatefulsets, ok := parameters["ignore_statefulsets"].(bool); ok && ignoreStatefulsets {
					ignored = true
					ignoredNodesCount++
				}
			case "ReplicaSet":
				if minHealthyReplicas, ok := parameters["min_healthy_replicas"].(string); ok && minHealthyReplicas != "" {
					replicaSet, err := client.GetReplicaSet(podName, namespace)
					if err != nil {
						otherErrorsCount++
						return
					}
					minHealthyReplicasValue, kind, err := helpers.ParseMinHealthyReplicas(minHealthyReplicas)
					if err != nil {
						otherErrorsCount++
						return
					}
					switch kind {
					case "absolut":
						healthyReplicasCount, err := kubernetes.GetHealthyReplicasCount(replicaSet)
						if err != nil {
							otherErrorsCount++
							return
						}
						if healthyReplicasCount < minHealthyReplicasValue {
							ignored = true
						}
					case "percent":
						healthyReplicasPercent, err := kubernetes.GetHealthyReplicasCount(replicaSet)
						if err != nil {
							otherErrorsCount++
							return
						}
						if healthyReplicasPercent < minHealthyReplicasValue {
							ignored = true
							ignoredNodesCount++
						}
					}
				}
			}

			if !ignored {
				eviction := &policyv1.Eviction{
					ObjectMeta: metav1.ObjectMeta{
						Name:      pod.GetName(),
						Namespace: pod.GetNamespace(),
					},
					DeleteOptions: &metav1.DeleteOptions{
						GracePeriodSeconds: gracePeriodSeconds,
					},
				}
				if err := client.PolicyV1().Evictions(pod.GetNamespace()).Evict(context.Background(), eviction); err != nil {
					evictionErrorsCount++
				}
			}
		}()
	}

	wg.Wait()

	if parameters["ignore_errors"].(bool) || evictionErrorsCount == 0 && otherErrorsCount == 0 {
		return utils.LogLine{
				Objects: objects,
				Output:  fmt.Sprintf("the node '%v' has been drained, errors are ignored: %v ignored pods, %v eviction errors, %v other errors", nodeName, ignoredNodesCount, evictionErrorsCount, otherErrorsCount),
				Status:  "success",
			},
			nil
	}
	return utils.LogLine{
			Objects: objects,
			Error:   fmt.Sprintf("the node '%v' has not been fully drained: %v eviction errors, %v other errors", nodeName, evictionErrorsCount, otherErrorsCount),
			Status:  "failure",
		},
		fmt.Errorf("the node '%v' has not been fully drained: %v eviction errors, %v other errors", nodeName, evictionErrorsCount, otherErrorsCount)
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
