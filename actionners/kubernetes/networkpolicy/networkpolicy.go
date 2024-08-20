package networkpolicy

import (
	"context"
	"fmt"
	"net"

	networkingv1 "k8s.io/api/networking/v1"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	AllowCIDR       []string `mapstructure:"allow_cidr" validate:"omitempty"`
	AllowNamespaces []string `mapstructure:"allow_namespaces" validate:"omitempty"`
}

const managedByStr string = "app.kubernetes.io/managed-by"

func Action(action *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"pod":       podName,
		"namespace": namespace,
	}
	client := kubernetes.GetClient()

	parameters := action.GetParameters()

	var config Config
	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}

	var owner string
	labels := make(map[string]string)

	if len(pod.OwnerReferences) != 0 {
		switch pod.OwnerReferences[0].Kind {
		case "DaemonSet":
			u, err2 := client.GetDaemonsetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
						Objects: objects,
						Error:   err2.Error(),
						Status:  utils.FailureStr,
					},
					nil,
					err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "StatefulSet":
			u, err2 := client.GetStatefulsetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
						Objects: objects,
						Error:   err2.Error(),
						Status:  utils.FailureStr,
					},
					nil,
					err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "ReplicaSet":
			u, err2 := client.GetReplicasetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
						Objects: objects,
						Error:   err2.Error(),
						Status:  utils.FailureStr,
					},
					nil,
					err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		}
	} else {
		owner = pod.ObjectMeta.Name
		labels = pod.ObjectMeta.Labels
	}

	if owner == "" || len(labels) == 0 {
		err3 := fmt.Errorf("can't find the owner and/or labels for the pod '%v' in namespace '%v'", podName, namespace)
		return utils.LogLine{
				Objects: objects,
				Error:   err3.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err3
	}

	delete(labels, "pod-template-hash")
	delete(labels, "pod-template-generation")
	delete(labels, "controller-revision-hash")
	labels[managedByStr] = utils.FalcoTalonStr

	selector := make(map[string]string)
	for i, j := range labels {
		if i != managedByStr {
			selector[i] = j
		}
	}

	payload := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      owner,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{"Egress"},
			PodSelector: metav1.LabelSelector{
				MatchLabels: selector,
			},
		},
	}

	np, err := createEgressRule(&config)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}

	if np != nil {
		payload.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{*np}
	}

	objects["networkpolicy"] = owner

	var output string
	_, err = client.Clientset.NetworkingV1().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		_, err = client.Clientset.NetworkingV1().NetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		output = fmt.Sprintf("the networkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
	} else {
		_, err = client.Clientset.NetworkingV1().NetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
		output = fmt.Sprintf("the networkpolicy '%v' in the namespace '%v' has been updated", owner, namespace)
	}
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  output,
		Status:  utils.SuccessStr,
	}, nil, nil
}

func createEgressRule(config *Config) (*networkingv1.NetworkPolicyEgressRule, error) {
	if len(config.AllowCIDR) == 0 && len(config.AllowNamespaces) == 0 {
		return nil, nil
	}

	np := make([]networkingv1.NetworkPolicyPeer, 0)
	if allowedCidr := config.AllowCIDR; len(allowedCidr) != 0 {
		for _, i := range allowedCidr {
			np = append(np,
				networkingv1.NetworkPolicyPeer{
					IPBlock: &networkingv1.IPBlock{
						CIDR: i,
					},
				},
			)
		}
	}
	if allowedNamespaces := config.AllowNamespaces; len(allowedNamespaces) != 0 {
		for _, i := range allowedNamespaces {
			np = append(np,
				networkingv1.NetworkPolicyPeer{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": i,
						},
					},
				},
			)
		}
	}
	return &networkingv1.NetworkPolicyEgressRule{To: np}, nil
}

func CheckParameters(action *rules.Action) error {
	parameters := action.GetParameters()

	var config Config

	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return err
	}

	for _, i := range config.AllowCIDR {
		if _, _, err2 := net.ParseCIDR(i); err2 != nil {
			return fmt.Errorf("wrong CIDR '%v'", i)
		}
	}

	err = utils.ValidateStruct(config)
	if err != nil {
		return err
	}

	return nil
}
