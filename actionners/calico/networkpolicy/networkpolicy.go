package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"strings"

	networkingv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calico "github.com/falco-talon/falco-talon/internal/calico/client"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	AllowCIDR       []string `mapstructure:"allow_cidr" validate:"omitempty"`
	AllowNamespaces []string `mapstructure:"allow_namespaces" validate:"omitempty"`
	Order           int      `mapstructure:"order" validate:"omitempty"`
}

const mask32 string = "/32"
const managedByStr string = "app.kubernetes.io/managed-by"

func Action(action *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

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

	objects := map[string]string{
		"pod":       podName,
		"namespace": namespace,
	}
	k8sClient := kubernetes.GetClient()
	calicoClient := calico.GetClient()

	pod, err := k8sClient.GetPod(podName, namespace)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	var owner string
	labels := make(map[string]string)

	if len(pod.OwnerReferences) != 0 {
		switch pod.OwnerReferences[0].Kind {
		case "DaemonSet":
			u, err2 := k8sClient.GetDaemonsetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				}, nil, err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "StatefulSet":
			u, err2 := k8sClient.GetStatefulsetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				}, nil, err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "ReplicaSet":
			u, err2 := k8sClient.GetReplicasetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				}, nil, err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		}
	} else {
		owner = pod.ObjectMeta.Name
		labels = pod.ObjectMeta.Labels
	}

	if owner == "" || len(labels) == 0 {
		err3 := fmt.Errorf("can't find the owner and/or labels for the pod '%v' in the namespace '%v'", podName, namespace)
		return utils.LogLine{
			Objects: objects,
			Error:   err3.Error(),
			Status:  utils.FailureStr,
		}, nil, err3
	}

	delete(labels, "pod-template-hash")
	delete(labels, "pod-template-generation")
	delete(labels, "controller-revision-hash")
	labels[managedByStr] = utils.FalcoTalonStr

	payload := networkingv3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      owner,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: networkingv3.NetworkPolicySpec{
			Types: []networkingv3.PolicyType{networkingv3.PolicyTypeEgress},
		},
	}

	order := float64(config.Order)
	payload.Spec.Order = &order

	var selector string
	for i, j := range labels {
		if i != managedByStr {
			selector += fmt.Sprintf(`%v == "%v" && `, i, j)
		}
	}

	payload.Spec.Selector = strings.TrimSuffix(selector, " && ")

	var allowCIDRRule, allowNamespacesRule *networkingv3.Rule

	if config.AllowCIDR == nil && config.AllowNamespaces == nil {
		allowCIDRRule = &networkingv3.Rule{
			Action: "Allow",
			Destination: networkingv3.EntityRule{
				Nets: []string{"0.0.0.0/0"},
			},
		}
		allowNamespacesRule = nil
	} else {
		allowCIDRRule = createAllowCIDREgressRule(&config)
		allowNamespacesRule = createAllowNamespaceEgressRule(&config)
	}

	denyRule := createDenyEgressRule([]string{event.GetRemoteIP() + mask32})
	if denyRule == nil {
		err2 := fmt.Errorf("can't create the rule for the networkpolicy '%v' in the namespace '%v'", owner, namespace)
		return utils.LogLine{
			Objects: objects,
			Error:   err2.Error(),
			Status:  utils.FailureStr,
		}, nil, err2
	}

	var output string
	var netpol *networkingv3.NetworkPolicy
	netpol, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		payload.Spec.Egress = []networkingv3.Rule{*denyRule}
		if allowCIDRRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowCIDRRule)
		}
		if allowNamespacesRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowNamespacesRule)
		}
		_, err2 := calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		if err2 != nil {
			if !errorsv1.IsAlreadyExists(err2) {
				return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				}, nil, err2
			}
			netpol, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
		} else {
			output = fmt.Sprintf("the caliconetworkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
			return utils.LogLine{
				Objects: objects,
				Output:  output,
				Status:  utils.SuccessStr,
			}, nil, nil
		}
	}
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}
	payload.ObjectMeta.ResourceVersion = netpol.ObjectMeta.ResourceVersion
	var denyCIDR []string
	for _, i := range netpol.Spec.Egress {
		if i.Action == "Deny" {
			denyCIDR = append(denyCIDR, i.Destination.Nets...)
		}
	}
	denyCIDR = append(denyCIDR, event.GetRemoteIP()+mask32)
	denyCIDR = utils.Deduplicate(denyCIDR)
	denyRule = createDenyEgressRule(denyCIDR)
	payload.Spec.Egress = []networkingv3.Rule{*denyRule}
	if allowCIDRRule != nil {
		payload.Spec.Egress = append(payload.Spec.Egress, *allowCIDRRule)
	}
	if allowNamespacesRule != nil {
		payload.Spec.Egress = append(payload.Spec.Egress, *allowNamespacesRule)
	}
	_, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}
	objects["caliconetworpolicy"] = owner
	output = fmt.Sprintf("the caliconetworkpolicy '%v' in the namespace '%v' has been updated", owner, namespace)

	return utils.LogLine{
		Objects: objects,
		Output:  output,
		Status:  utils.SuccessStr,
	}, nil, nil
}

func createAllowCIDREgressRule(config *Config) *networkingv3.Rule {
	if len(config.AllowCIDR) == 0 {
		return nil
	}

	rule := networkingv3.Rule{
		Action:      "Allow",
		Destination: networkingv3.EntityRule{},
	}

	rule.Destination.Nets = append(rule.Destination.Nets, config.AllowCIDR...)

	return &rule
}

func createAllowNamespaceEgressRule(config *Config) *networkingv3.Rule {
	if len(config.AllowNamespaces) == 0 {
		return nil
	}

	rule := networkingv3.Rule{
		Action:      "Allow",
		Destination: networkingv3.EntityRule{},
	}

	allowedNamespacesStr := []string{}
	allowedNamespacesStr = append(allowedNamespacesStr, config.AllowNamespaces...)

	selector := "kubernetes.io/metadata.name in { '"
	selector += strings.Join(allowedNamespacesStr, "', '")
	selector += "' }"

	rule.Destination.NamespaceSelector = selector

	return &rule
}

func createDenyEgressRule(ips []string) *networkingv3.Rule {
	r := networkingv3.Rule{
		Action: "Deny",
		Destination: networkingv3.EntityRule{
			Nets: ips,
		},
	}

	return &r
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
