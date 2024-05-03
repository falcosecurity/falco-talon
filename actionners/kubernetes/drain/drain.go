package drain

import (
	"context"
	"fmt"
	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
	"github.com/go-playground/validator/v10"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"regexp"
	"strconv"
	"strings"
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
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	node, err := client.GetNodeFromPod(pod)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	objects["node"] = node.Name

	pods, err := client.Clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", node.GetName()),
	})

	for _, p := range pods.Items {

		if parameters["ignore_daemonsets"] != nil || parameters["ignore_statefulsets"] != nil || parameters["min_healthy_replicas"] != nil {
			pod, err := client.GetPod(p.Name, p.Namespace)
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
								Result:  fmt.Sprintf("the pod %v in the namespace %v belongs to a Daemonset and ignore_daemonsets is true", p.Name, p.Namespace),
								Status:  "ignored",
							},
							nil
					}
				case "StatefulSet":
					if parameters["ignore_statefulsets"].(bool) {
						return utils.LogLine{
								Objects: objects,
								Result:  fmt.Sprintf("the pod %v in the namespace %v belongs to a Statefulset and ignore_statefulsets is true", p.Name, p.Namespace),
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
									Error:   fmt.Sprintf("can't find the replicaset for the pod %v in namespace %v", p.Name, p.Namespace),
									Status:  "failure",
								},
								fmt.Errorf("can't find the replicaset for the pod %v in namespace %v", p.Name, p.Namespace)
						}
						if strings.Contains(fmt.Sprintf("%v", parameters["min_healthy_replicas"]), "%") {
							v, _ := strconv.ParseInt(strings.Split(parameters["min_healthy_replicas"].(string), "%")[0], 10, 64)
							if v > int64(100*u.Status.ReadyReplicas/u.Status.Replicas) {
								return utils.LogLine{
										Objects: objects,
										Result:  fmt.Sprintf("not enough healthy pods in the replicaset of the pod %v in namespace %v", p.Name, p.Namespace),
										Status:  "ignored",
									},
									fmt.Errorf("not enough healthy pods in the replicaset of the pod %v in namespace %v", p.Name, p.Namespace)
							}
						} else {
							v, _ := strconv.ParseInt(parameters["min_healthy_replicas"].(string), 10, 64)
							if v > int64(u.Status.ReadyReplicas) {
								return utils.LogLine{
										Objects: objects,
										Result:  fmt.Sprintf("not enough healthy pods in the replicaset of the pod %v in namespace %v", p.Name, p.Namespace),
										Status:  "ignored",
									},
									fmt.Errorf("not enough healthy pods in the replicaset of the pod %v in namespace %v", p.Name, p.Namespace)
							}
						}
					}
				}
			}
		}

		delOpts := metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds}
		evictionGroupVersion, err := CheckEvictionSupport(client)
		if err != nil {
			return utils.LogLine{
				Objects: objects,
				Status:  "failure",
				Error:   err.Error(),
			}, err
		}

		switch evictionGroupVersion {
		case policyv1.SchemeGroupVersion:
			// send policy/v1 if the server supports it
			eviction := &policyv1.Eviction{
				ObjectMeta: metav1.ObjectMeta{
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				DeleteOptions: &delOpts,
			}
			err := client.PolicyV1().Evictions(eviction.Namespace).Evict(context.TODO(), eviction)
			if err != nil {
				return utils.LogLine{
					Objects: objects,
					Status:  "failure",
					Error:   err.Error(),
				}, err
			}

		default:
			// otherwise, fall back to policy/v1beta1, supported by all servers that support the eviction subresource
			eviction := &policyv1beta1.Eviction{
				ObjectMeta: metav1.ObjectMeta{
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				DeleteOptions: &delOpts,
			}
			err := client.Clientset.PolicyV1beta1().Evictions(p.Namespace).Evict(context.Background(), eviction)
			if err != nil {
				return utils.LogLine{
					Objects: objects,
					Status:  "failure",
					Error:   err.Error(),
				}, err
			}
		}
	}
	return utils.LogLine{
			Objects: objects,
			Output:  fmt.Sprintf("the node '%v' has been drained", podName),
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

func CheckEvictionSupport(client *kubernetes.Client) (schema.GroupVersion, error) {
	discoveryClient := client.Clientset.Discovery()

	// version info available in subresources since v1.8.0 in https://github.com/kubernetes/kubernetes/pull/49971
	resourceList, err := discoveryClient.ServerResourcesForGroupVersion("v1")
	if err != nil {
		return schema.GroupVersion{}, err
	}
	for _, resource := range resourceList.APIResources {
		if resource.Name == EvictionSubresource && resource.Kind == EvictionKind && len(resource.Group) > 0 && len(resource.Version) > 0 {
			return schema.GroupVersion{Group: resource.Group, Version: resource.Version}, nil
		}
	}
	return schema.GroupVersion{}, nil
}
