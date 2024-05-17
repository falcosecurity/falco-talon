package drain

import (
	"context"
	"fmt"
	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/kubernetes/helpers"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
	"github.com/go-playground/validator/v10"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"regexp"
	"strings"
	"sync"
)

const (
	validatorName = "is_absolut_or_percent"
	// EvictionKind represents the kind of evictions object
	EvictionKind = "Eviction"
	// EvictionSubresource represents the kind of evictions object as pod's subresource
	EvictionSubresource = "pods/eviction"
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
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, err
	}
	objects["node"] = node.Name

	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, err
	}

	pods, err := client.Clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", node.GetName()),
	})
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, err
	}

	var aggregatedLog utils.LogLine
	aggregatedLog.Objects = make(map[string]string)
	var allErrors []string
	var ignoredPods []string

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range pods.Items {
		wg.Add(1)

		go func(p corev1.Pod) {
			defer wg.Done()
			line, err, ignored := helpers.VerifyIfPodWillBeIgnored(parameters, client, p, objects)

			mu.Lock()
			defer mu.Unlock()

			if ignored {
				aggregatedLog.Output += line.Output + "; "
				ignoredPods = append(ignoredPods, p.Name)
				return
			}
			if err != nil {
				allErrors = append(allErrors, err.Error())
				return
			}

			err = performEviction(client, p, gracePeriodSeconds)
			if err != nil {
				allErrors = append(allErrors, err.Error())
			}
		}(p)
	}
	wg.Wait()

	if len(allErrors) > 0 {
		aggregatedLog.Error = strings.Join(allErrors, "; ")
		aggregatedLog.Status = "failure"
	} else {
		aggregatedLog.Status = "success"
		aggregatedLog.Output = fmt.Sprintf("Node '%v' drained, ignored pods: %v", node.Name, strings.Join(ignoredPods, ", "))
	}

	return aggregatedLog, nil
}

func performEviction(client *kubernetes.Client, pod corev1.Pod, gracePeriodSeconds *int64) error {
	delOpts := metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds}
	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
		DeleteOptions: &delOpts,
	}

	utils.PrintLog("debug", utils.LogLine{Message: fmt.Sprintf("Evicting pod: %v.", pod.Name)})

	if pod.Namespace != "falco" {
		return client.PolicyV1().Evictions(eviction.Namespace).Evict(context.Background(), eviction)
	} else {
		return nil
	}
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
