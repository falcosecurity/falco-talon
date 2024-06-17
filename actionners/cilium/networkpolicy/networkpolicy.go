package networkpolicy

import (
	"context"
	"fmt"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"

	cilium "github.com/falco-talon/falco-talon/internal/cilium/client"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	AllowCIDR       []string `mapstructure:"allow_cidr" validate:"omitempty"`
	AllowNamespaces []string `mapstructure:"allow_namespaces" validate:"omitempty"`
}

const mask32 string = "/32"
const managedByStr string = "app.kubernetes.io/managed-by"
const netpolDescription string = "Network policy created by Talon"
const namespaceKey = "kubernetes.io/metadata.name"

func Action(action *rules.Action, event *events.Event) (utils.LogLine, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()
	parameters := action.GetParameters()

	var actionConfig Config
	err := utils.DecodeParams(action.GetParameters(), &actionConfig)
	if err != nil {
		return utils.LogLine{
				Objects: nil,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	objects := map[string]string{
		"pod":       podName,
		"namespace": namespace,
	}

	k8sClient := kubernetes.GetClient()
	ciliumClient := cilium.GetClient()

	pod, err := k8sClient.GetPod(podName, namespace)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
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
						Status:  "failure",
					},
					err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "StatefulSet":
			u, err2 := k8sClient.GetStatefulsetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
						Objects: objects,
						Error:   err2.Error(),
						Status:  "failure",
					},
					err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "ReplicaSet":
			u, err2 := k8sClient.GetReplicasetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
						Objects: objects,
						Error:   err2.Error(),
						Status:  "failure",
					},
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
		err3 := fmt.Errorf("can't find the owner and/or labels for the pod '%v' in the namespace '%v'", podName, namespace)
		return utils.LogLine{
				Objects: objects,
				Error:   err3.Error(),
				Status:  "failure",
			},
			err3
	}

	delete(labels, "pod-template-hash")
	delete(labels, "pod-template-generation")
	delete(labels, "controller-revision-hash")

	resourceLabels := make(map[string]string)
	for key, value := range labels {
		resourceLabels[key] = value
	}
	resourceLabels[managedByStr] = utils.FalcoTalonStr

	payload := v2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      owner,
			Namespace: namespace,
			Labels:    resourceLabels,
		},
		Spec: &api.Rule{
			Description: netpolDescription,
		},
		Status: v2.CiliumNetworkPolicyStatus{},
	}

	payload.Spec.EndpointSelector = api.EndpointSelector{
		LabelSelector: &v1.LabelSelector{MatchLabels: labels},
	}

	var allowCIDRRule, allowNamespacesRule *api.EgressRule

	if parameters["allow_cidr"] == nil && parameters["allow_namespaces"] == nil {
		allowCIDRRule = &api.EgressRule{
			EgressCommonRule: api.EgressCommonRule{
				ToCIDR: api.CIDRSlice{"0.0.0.0/0"},
			},
		}
	} else {
		allowCIDRRule = createAllowCIDREgressRule(actionConfig)
		allowNamespacesRule = createAllowNamespaceEgressRule(actionConfig)
	}

	denyRule := createDenyEgressRule([]string{event.GetRemoteIP() + mask32})
	if denyRule == nil {
		err2 := fmt.Errorf("can't create deny rule for the networkpolicy '%v' in the namespace '%v'", owner, namespace)
		return utils.LogLine{
				Objects: objects,
				Error:   err2.Error(),
				Status:  "failure",
			},
			err2
	}

	var output string
	var netpol *v2.CiliumNetworkPolicy

	netpol, err = ciliumClient.CiliumV2().CiliumNetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		payload.Spec.EgressDeny = []api.EgressDenyRule{*denyRule}
		if allowCIDRRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowCIDRRule)
		}
		if allowNamespacesRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowNamespacesRule)
		}
		_, err2 := ciliumClient.CiliumV2().CiliumNetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		if err2 != nil {
			return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  "failure",
				},
				err2
		}
		output = fmt.Sprintf("the ciliumnetworkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
		return utils.LogLine{
				Objects: objects,
				Output:  output,
				Status:  "success",
			},
			nil
	}
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	payload.ObjectMeta.ResourceVersion = netpol.ObjectMeta.ResourceVersion
	payload.Spec.Egress = netpol.Spec.Egress
	payload.Spec.EgressDeny = netpol.Spec.EgressDeny

	denyRule = createDenyEgressRule([]string{event.GetRemoteIP() + mask32})

	for _, egressDenyRule := range payload.Spec.EgressDeny {
		if !denyEgressRuleExists(egressDenyRule, *denyRule) {
			payload.Spec.EgressDeny = append(payload.Spec.EgressDeny, *denyRule)
		}
	}

	for _, egressRule := range payload.Spec.Egress {
		if !egressRuleExists(egressRule, *allowCIDRRule) && allowCIDRRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowCIDRRule)
		}
		if !egressRuleExists(egressRule, *allowNamespacesRule) && allowNamespacesRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowNamespacesRule)
		}
	}

	_, err = ciliumClient.CiliumV2().CiliumNetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}
	output = fmt.Sprintf("the ciliumnetworkpolicy '%v' in the namespace '%v' has been updated", owner, namespace)
	objects["NetworkPolicy"] = owner

	return utils.LogLine{
			Objects: objects,
			Output:  output,
			Status:  "success",
		},
		nil
}

func createAllowNamespaceEgressRule(actionConfig Config) *api.EgressRule {
	if len(actionConfig.AllowCIDR) == 0 {
		return nil
	}

	selector := api.EndpointSelector{
		LabelSelector: &v1.LabelSelector{
			MatchExpressions: []v1.LabelSelectorRequirement{
				{
					Key:      namespaceKey,
					Operator: v1.LabelSelectorOpIn,
					Values:   actionConfig.AllowNamespaces,
				},
			},
		},
	}

	rule := api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToEndpoints: []api.EndpointSelector{selector},
		},
	}

	return &rule
}

func createAllowCIDREgressRule(actionConfig Config) *api.EgressRule {
	if len(actionConfig.AllowCIDR) == 0 {
		return nil
	}

	var apiCidr api.CIDRSlice

	for _, cidr := range actionConfig.AllowCIDR {
		apiCidr = append(apiCidr, api.CIDR(cidr))
	}

	rule := api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: apiCidr,
		},
	}

	return &rule
}

func createDenyEgressRule(ips []string) *api.EgressDenyRule {
	var cidrSlice api.CIDRSlice
	for _, ip := range ips {
		cidrSlice = append(cidrSlice, api.CIDR(ip))
	}
	r := api.EgressDenyRule{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: cidrSlice,
		},
	}

	return &r
}

func egressRuleExists(rule api.EgressRule, newRule api.EgressRule) bool {
	if rule.DeepEqual(&newRule) {
		return true
	}
	return false
}

func denyEgressRuleExists(denyEgressRule api.EgressDenyRule, newDenyEgressRule api.EgressDenyRule) bool {
	if denyEgressRule.DeepEqual(&newDenyEgressRule) {
		return true
	}
	return false
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
