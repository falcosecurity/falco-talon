package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	networkingv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calico "github.com/Falco-Talon/falco-talon/internal/calico/client"

	"github.com/Falco-Talon/falco-talon/internal/events"
	kubernetes "github.com/Falco-Talon/falco-talon/internal/kubernetes/client"
	"github.com/Falco-Talon/falco-talon/internal/rules"
	"github.com/Falco-Talon/falco-talon/utils"
)

const mask32 string = "/32"

func Action(action *rules.Action, event *events.Event) (utils.LogLine, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	parameters := action.GetParameters()

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

	if parameters["order"] != nil {
		order := float64(parameters["order"].(int))
		payload.Spec.Order = &order
	}

	var selector string
	for i, j := range labels {
		selector += fmt.Sprintf(`%v == "%v" &&`, i, j)
	}

	payload.Spec.Selector = strings.TrimSuffix(selector, " &&")

	allowRule := createAllowEgressRule(action)
	denyRule := createDenyEgressRule([]string{event.GetRemoteIP() + mask32})
	if denyRule == nil {
		err2 := fmt.Errorf("can't create the rule for the networkpolicy '%v' in the namespace '%v'", owner, namespace)
		return utils.LogLine{
				Objects: objects,
				Error:   err2.Error(),
				Status:  "failure",
			},
			err2
	}

	var output string
	netpol, err := calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		payload.Spec.Egress = []networkingv3.Rule{*denyRule}
		payload.Spec.Egress = append(payload.Spec.Egress, *allowRule)
		_, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		output = fmt.Sprintf("the networkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
	} else if err == nil {
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
		payload.Spec.Egress = append(payload.Spec.Egress, *allowRule)
		_, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
		if errorsv1.IsAlreadyExists(err) {
			time.Sleep(1 * time.Second)
			_, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
		}
		output = fmt.Sprintf("the networkpolicy '%v' in the namespace '%v' has been updated", owner, namespace)
	}
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}
	objects["NetworkPolicy"] = owner
	return utils.LogLine{
			Objects: objects,
			Output:  output,
			Status:  "success",
		},
		nil
}

func createAllowEgressRule(action *rules.Action) *networkingv3.Rule {
	var allowCIDR []string
	if action.GetParameters()["allow"] != nil {
		if allowedCidr := action.GetParameters()["allow"].([]interface{}); len(allowedCidr) != 0 {
			for _, i := range allowedCidr {
				allowedCidr = append(allowedCidr, i.(string))
			}
		} else {
			allowCIDR = append(allowCIDR, "0.0.0.0/0")
		}
	} else {
		allowCIDR = append(allowCIDR, "0.0.0.0/0")
	}

	rule := &networkingv3.Rule{
		Action: "Allow",
		Destination: networkingv3.EntityRule{
			Nets: allowCIDR,
		},
	}

	return rule
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
	if err := utils.CheckParameters(parameters, "allow", utils.SliceInterfaceStr, nil, false); err != nil {
		return err
	}
	if parameters["allow"] != nil {
		if p := parameters["allow"].([]interface{}); len(p) != 0 {
			for _, i := range p {
				if _, _, err := net.ParseCIDR(i.(string)); err != nil {
					return fmt.Errorf("wrong CIDR '%v'", i)
				}
			}
		}
	}
	if err := utils.CheckParameters(parameters, "order", utils.IntStr, nil, false); err != nil {
		return err
	}
	return nil
}
