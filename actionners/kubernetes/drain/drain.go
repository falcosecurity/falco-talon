package drain

import (
	"context"
	"fmt"
	"sync"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	helpers "github.com/falco-talon/falco-talon/actionners/kubernetes/helpers"
	"github.com/falco-talon/falco-talon/internal/events"
	k8sChecks "github.com/falco-talon/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/models"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	Name          string = "drain"
	Category      string = "kubernetes"
	Description   string = "Drain a pod"
	Source        string = "syscalls"
	Continue      bool   = true
	UseContext    bool   = false
	AllowOutput   bool   = false
	RequireOutput bool   = false
	Permissions   string = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: falco-talon
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
  - list
- apiGroups:
  - ""
  resources:
  - pods/eviction
  verbs:
  - get
  - create
- apiGroups:
  - apps
  resources:
  - replicasets
  verbs:
  - get
`
	Example string = `- action: Drain the node
  actionner: kubernetes:drain
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

const (
	// EvictionKind represents the kind of evictions object
	EvictionKind = "Eviction"
	// EvictionSubresource represents the kind of evictions object as pod's subresource
	EvictionSubresource = "pods/eviction"
)

type Parameters struct {
	MinHealthyReplicas string `mapstructure:"min_healthy_replicas" validate:"omitempty,is_absolut_or_percent"`
	IgnoreErrors       bool   `mapstructure:"ignore_errors" validate:"omitempty"`
	IgnoreDaemonsets   bool   `mapstructure:"ignore_daemonsets" validate:"omitempty"`
	IgnoreStatefulSets bool   `mapstructure:"ignore_statefulsets" validate:"omitempty"`
	GracePeriodSeconds int    `mapstructure:"grace_period_seconds" validate:"omitempty"`
}

type Actionner struct{}

func Register() *Actionner {
	return new(Actionner)
}

func (a Actionner) Init() error {
	return k8s.Init()
}

func (a Actionner) Information() models.Information {
	return models.Information{
		Name:                 Name,
		FullName:             Category + ":" + Name,
		Category:             Category,
		Description:          Description,
		Source:               Source,
		RequiredOutputFields: RequiredOutputFields,
		Permissions:          Permissions,
		Example:              Example,
		Continue:             Continue,
		AllowOutput:          AllowOutput,
		RequireOutput:        RequireOutput,
	}
}
func (a Actionner) Parameters() models.Parameters {
	return Parameters{
		MinHealthyReplicas: "",
		IgnoreErrors:       false,
		IgnoreDaemonsets:   false,
		IgnoreStatefulSets: false,
		GracePeriodSeconds: 0,
	}
}

func (a Actionner) Checks(event *events.Event, _ *rules.Action) error {
	return k8sChecks.CheckPodExist(event)
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()
	objects := map[string]string{}

	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	gracePeriodSeconds := new(int64)
	*gracePeriodSeconds = int64(parameters.GracePeriodSeconds)

	client := k8s.GetClient()
	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	node, err := client.GetNodeFromPod(pod)
	if err != nil {
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
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
			Status:  utils.FailureStr,
		}, nil, err
	}

	var ignoredPodsCount, evictionErrorsCount, otherErrorsCount int

	var wg sync.WaitGroup

	for _, p := range pods.Items {
		wg.Add(1)
		p := p // loopclosure: loop variable p captured by func literal
		go func() {
			defer wg.Done()

			ownerKind, err := k8s.GetOwnerKind(p)
			if err != nil {
				utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting pod '%v' owner kind: %v", p.Name, err)})
				otherErrorsCount++
				return
			}

			switch ownerKind {
			case "DaemonSet":
				if parameters.IgnoreDaemonsets {
					ignoredPodsCount++
				}
			case "StatefulSet":
				if parameters.IgnoreStatefulSets {
					ignoredPodsCount++
				}
			case "ReplicaSet":
				replicaSetName, err := k8s.GetOwnerName(p)
				if err != nil {
					utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting pod owner name: %v", err)})
					otherErrorsCount++
				}
				if parameters.MinHealthyReplicas != "" {
					replicaSet, err := client.GetReplicaSet(replicaSetName, p.Namespace)
					if err != nil {
						utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting replica set for pod '%v': %v", p.Name, err)})
						otherErrorsCount++
						return
					}
					minHealthyReplicasValue, kind, err := helpers.ParseMinHealthyReplicas(parameters.MinHealthyReplicas)
					if err != nil {
						utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error parsing min_healthy_replicas: %v", err)})
						otherErrorsCount++
						return
					}
					switch kind {
					case "absolut":
						healthyReplicasCount, err := k8s.GetHealthyReplicasCount(replicaSet)
						if err != nil {
							utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting health replicas count for pod '%v': %v", p.Name, err)})
							otherErrorsCount++
							return
						}
						if healthyReplicasCount < minHealthyReplicasValue {
							return
						}
					case "percent":
						healthyReplicasValue, err := k8s.GetHealthyReplicasCount(replicaSet)
						minHealthyReplicasAbsoluteValue := int64(float64(minHealthyReplicasValue) / 100.0 * float64(healthyReplicasValue))
						if err != nil {
							utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting health replicas count for pod '%v': %v", p.Name, err)})
							otherErrorsCount++
							return
						}
						if healthyReplicasValue < minHealthyReplicasAbsoluteValue {
							ignoredPodsCount++
							return
						}
					}
				}
			}

			eviction := &policyv1.Eviction{
				ObjectMeta: metav1.ObjectMeta{
					Name:      p.GetName(),
					Namespace: p.GetNamespace(),
				},
				DeleteOptions: &metav1.DeleteOptions{
					GracePeriodSeconds: gracePeriodSeconds,
				},
			}
			if err := client.PolicyV1().Evictions(pod.GetNamespace()).Evict(context.Background(), eviction); err != nil {
				utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error evicting pod '%v': %v", p.Name, err)})
				evictionErrorsCount++
			}
		}()
	}

	wg.Wait()

	if parameters.IgnoreErrors || (evictionErrorsCount == 0 && otherErrorsCount == 0) {
		return utils.LogLine{
			Objects: objects,
			Output:  fmt.Sprintf("the node '%v' has been drained, errors are ignored: %v ignored pods, %v eviction errors, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, otherErrorsCount),
			Status:  utils.SuccessStr,
		}, nil, nil
	}
	return utils.LogLine{
		Objects: objects,
		Error:   fmt.Sprintf("the node '%v' has not been fully drained: %v pods ignored, %v eviction errors, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, otherErrorsCount),
		Status:  utils.FailureStr,
	}, nil, fmt.Errorf("the node '%v' has not been fully drained: %v eviction errors, %v other errors", nodeName, evictionErrorsCount, otherErrorsCount)
}

func (a Actionner) CheckParameters(action *rules.Action) error {
	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	err = utils.AddCustomValidation(helpers.ValidatorMinHealthyReplicas, helpers.ValidateMinHealthyReplicas)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(parameters)
	if err != nil {
		return err
	}

	return nil
}
