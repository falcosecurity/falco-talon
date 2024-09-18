package drain

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/falco-talon/falco-talon/actionners/kubernetes/helpers"

	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"

	"github.com/falco-talon/falco-talon/internal/events"
	k8sChecks "github.com/falco-talon/falco-talon/internal/kubernetes/checks"
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

type Parameters struct {
	MinHealthyReplicas           string   `mapstructure:"min_healthy_replicas" validate:"omitempty,is_absolut_or_percent"`
	WaitPeriodExcludedNamespaces []string `mapstructure:"wait_period_excluded_namespaces" validate:"omitempty"`
	IgnoreErrors                 bool     `mapstructure:"ignore_errors" validate:"omitempty"`
	IgnoreDaemonsets             bool     `mapstructure:"ignore_daemonsets" validate:"omitempty"`
	IgnoreStatefulSets           bool     `mapstructure:"ignore_statefulsets" validate:"omitempty"`
	GracePeriodSeconds           int      `mapstructure:"grace_period_seconds" validate:"omitempty"`
	MaxWaitPeriod                int      `mapstructure:"max_wait_period" validate:"omitempty"`
}

type Actionner struct{}

func Register() *Actionner {
	return new(Actionner)
}

func (a Actionner) Init() error {
	return kubernetes.Init()
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
		MinHealthyReplicas:           "",
		IgnoreErrors:                 false,
		IgnoreDaemonsets:             false,
		IgnoreStatefulSets:           false,
		GracePeriodSeconds:           0,
		MaxWaitPeriod:                0,
		WaitPeriodExcludedNamespaces: []string{},
	}
}

func (a Actionner) Checks(event *events.Event, _ *rules.Action) error {
	return k8sChecks.CheckPodExist(event)
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	client := kubernetes.GetClient()
	return a.RunWithClient(*client, event, action)
}

func (a Actionner) RunWithClient(client kubernetes.DrainClient, event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
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

	pods, err := client.ListPods(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	var podState atomic.Value

	initialPodState := make(map[string]bool)
	for _, p := range pods.Items {
		key := fmt.Sprintf("%s/%s", p.Namespace, p.Name)
		initialPodState[key] = true
	}
	podState.Store(initialPodState)
	stopListingDone := make(chan struct{})

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopListingDone:
				return
			case <-ticker.C:
				pods2, err2 := client.ListPods(context.Background(), metav1.ListOptions{
					FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
				})
				if err2 != nil {
					utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error listing pods on node '%v': %v", nodeName, err2)})
					continue
				}

				newPodState := make(map[string]bool)
				for _, p := range pods2.Items {
					key := fmt.Sprintf("%s/%s", p.Namespace, p.Name)
					newPodState[key] = true
				}
				podState.Store(newPodState)
			}
		}
	}()

	var (
		ignoredPodsCount              int
		evictionErrorsCount           int
		evictionWaitPeriodErrorsCount int
		otherErrorsCount              int
		countersMutex                 sync.Mutex
	)

	var wg sync.WaitGroup

	for _, p := range pods.Items {
		wg.Add(1)
		go func(pod corev1.Pod) {
			defer wg.Done()

			ownerKind, err := kubernetes.GetOwnerKind(p)
			if err != nil {
				utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting pod '%v' owner kind: %v", p.Name, err)})
				countersMutex.Lock()
				otherErrorsCount++
				countersMutex.Unlock()
				return
			}

			switch ownerKind {
			case "DaemonSet":
				if parameters.IgnoreDaemonsets {
					countersMutex.Lock()
					ignoredPodsCount++
					countersMutex.Unlock()
					return
				}
			case "StatefulSet":
				if parameters.IgnoreStatefulSets {
					countersMutex.Lock()
					ignoredPodsCount++
					countersMutex.Unlock()
					return
				}
			case "ReplicaSet":
				replicaSetName, err := kubernetes.GetOwnerName(p)
				if err != nil {
					utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting pod owner name: %v", err)})
					countersMutex.Lock()
					otherErrorsCount++
					countersMutex.Unlock()
					return
				}
				if parameters.MinHealthyReplicas != "" {
					replicaSet, err := client.GetReplicaSet(replicaSetName, p.Namespace)
					if err != nil {
						utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting replica set for pod '%v': %v", p.Name, err)})
						countersMutex.Lock()
						otherErrorsCount++
						countersMutex.Unlock()
						return
					}
					minHealthyReplicasValue, kind, err := helpers.ParseMinHealthyReplicas(parameters.MinHealthyReplicas)
					if err != nil {
						utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error parsing min_healthy_replicas: %v", err)})
						countersMutex.Lock()
						otherErrorsCount++
						countersMutex.Unlock()
						return
					}
					switch kind {
					case "absolut":
						healthyReplicasCount, err := kubernetes.GetHealthyReplicasCount(replicaSet)
						if err != nil {
							utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting health replicas count for pod '%v': %v", p.Name, err)})
							countersMutex.Lock()
							otherErrorsCount++
							countersMutex.Unlock()
							return
						}
						if healthyReplicasCount < minHealthyReplicasValue {
							countersMutex.Lock()
							ignoredPodsCount++
							countersMutex.Unlock()
							return
						}
					case "percent":
						healthyReplicasValue, err := kubernetes.GetHealthyReplicasCount(replicaSet)
						minHealthyReplicasAbsoluteValue := int64(float64(minHealthyReplicasValue) / 100.0 * float64(healthyReplicasValue))
						if err != nil {
							utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting health replicas count for pod '%v': %v", p.Name, err)})
							countersMutex.Lock()
							otherErrorsCount++
							countersMutex.Unlock()
							return
						}
						if healthyReplicasValue < minHealthyReplicasAbsoluteValue {
							countersMutex.Lock()
							ignoredPodsCount++
							countersMutex.Unlock()
							return
						}
					}
				}
			}

			if err := client.EvictPod(p); err != nil {
				utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error evicting pod '%v': %v", p.Name, err)})
				countersMutex.Lock()
				evictionErrorsCount++
				countersMutex.Unlock()
				return
			}

			if parameters.MaxWaitPeriod > 0 {
				timeout := time.After(time.Duration(parameters.MaxWaitPeriod) * time.Second)
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-timeout:
						utils.PrintLog("error", utils.LogLine{Message: fmt.Sprintf("pod '%v' did not terminate within the max_wait_period", pod.Name)})
						countersMutex.Lock()
						evictionWaitPeriodErrorsCount++
						countersMutex.Unlock()
						return

					case <-ticker.C:
						key := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
						currentPodState := podState.Load().(map[string]bool)
						if _, ok := currentPodState[key]; !ok {
							return
						}
					}
				}
			}
		}(p)
	}

	wg.Wait()
	close(stopListingDone)

	if parameters.IgnoreErrors || (evictionErrorsCount == 0 && otherErrorsCount == 0 && evictionWaitPeriodErrorsCount == 0) {
		return utils.LogLine{
			Objects: objects,
			Output:  fmt.Sprintf("the node '%v' has been drained, errors are ignored: %v ignored pods, %v eviction errors, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, otherErrorsCount),
			Status:  utils.SuccessStr,
		}, nil, nil
	}
	return utils.LogLine{
		Objects: objects,
		Error:   fmt.Sprintf("the node '%v' has not been fully drained: %v pods ignored, %v eviction errors, %v were not evicted during max_wait_period, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, evictionWaitPeriodErrorsCount, otherErrorsCount),
		Status:  utils.FailureStr,
	}, nil, fmt.Errorf("the node '%v' has not been fully drained: %v pods ignored, %v eviction errors, %v were not evicted during max_wait_period, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, evictionWaitPeriodErrorsCount, otherErrorsCount)
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
