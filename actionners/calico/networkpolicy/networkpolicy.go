package networkpolicy

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	networkingv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calico "github.com/Falco-Talon/falco-talon/internal/calico/client"

	"github.com/Falco-Talon/falco-talon/internal/events"
	kubernetes "github.com/Falco-Talon/falco-talon/internal/kubernetes/client"
	"github.com/Falco-Talon/falco-talon/internal/rules"
	"github.com/Falco-Talon/falco-talon/utils"
)

func Action(_ *rules.Action, event *events.Event) (utils.LogLine, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

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

	var selector string
	for i, j := range labels {
		selector += fmt.Sprintf(`%v == "%v" &&`, i, j)
	}

	payload.Spec.Selector = strings.TrimSuffix(selector, " &&")

	r, err := createEgressRule(event)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	var output string
	netpol, err := calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		payload.Spec.Egress = []networkingv3.Rule{*r}
		_, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		output = fmt.Sprintf("the networkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
	} else {
		resourceVersion := netpol.ObjectMeta.ResourceVersion
		resourceVersionInt, err2 := strconv.ParseUint(resourceVersion, 0, 64)
		if err2 != nil {
			err = fmt.Errorf("can't upgrade the resource version for the networkpolicy '%v' in the namespace '%v'", payload.ObjectMeta.Name, namespace)
		} else {
			payload.ObjectMeta.ResourceVersion = fmt.Sprintf("%v", resourceVersionInt)
			netpol.Spec.Egress = append(netpol.Spec.Egress, *r)
			payload.Spec.Egress = netpol.Spec.Egress
			_, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
			output = fmt.Sprintf("the networkpolicy '%v' in the namespace '%v' has been updated", owner, namespace)
		}
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

func createEgressRule(event *events.Event) (*networkingv3.Rule, error) {
	port, err := strconv.ParseUint(event.GetRemotePort(), 0, 16)
	if err != nil {
		return nil, err
	}
	proto := numorstring.ProtocolFromString("TCP")
	r := networkingv3.Rule{
		Action:   "Deny",
		Protocol: &proto,
		Destination: networkingv3.EntityRule{
			Nets: []string{event.GetRemoteIP() + "/32"},
			Ports: []numorstring.Port{
				{
					MinPort: uint16(port),
					MaxPort: uint16(port),
				},
			},
		},
	}

	return &r, nil
}
