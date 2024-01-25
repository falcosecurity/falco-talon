package networkpolicy

import (
	"context"
	"fmt"
	"net"

	v1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var NetworkPolicy = func(rule *rules.Rule, action *rules.Action, event *events.Event) (utils.LogLine, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"Pod":       podName,
		"Namespace": namespace,
	}
	client := kubernetes.GetClient()

	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	labels := make(map[string]string)
	var owner string

	if len(pod.OwnerReferences) != 0 {
		switch pod.OwnerReferences[0].Kind {
		case "DaemonSet":
			u, errG := client.GetDaemonsetFromPod(pod)
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
						Error:   fmt.Sprintf("can't find the daemonset for the pod %v in namespace %v", podName, namespace),
						Status:  "failure",
					},
					fmt.Errorf("can't find the daemonset for the pod %v in namespace %v", podName, namespace)
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
			if owner == "" || len(labels) == 0 {
				return utils.LogLine{
						Objects: objects,
						Error:   fmt.Sprintf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace),
						Status:  "failure",
					},
					fmt.Errorf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace)
			}
		case "StatefulSet":
			u, errG := client.GetStatefulsetFromPod(pod)
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
						Error:   fmt.Sprintf("can't find the statefulset for the pod %v in namespace %v", podName, namespace),
						Status:  "failure",
					},
					fmt.Errorf("can't find the statefulset for the pod %v in namespace %v", podName, namespace)
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
			if owner == "" || len(labels) == 0 {
				return utils.LogLine{
						Objects: objects,
						Error:   fmt.Sprintf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace),
						Status:  "failure",
					},
					fmt.Errorf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace)
			}
		case "ReplicaSet":
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
						Error:   fmt.Sprintf("can't find the replicaset for the pod %v in namespace %v", podName, namespace),
						Status:  "failure",
					},
					fmt.Errorf("can't find the replicaset for the pod %v in namespace %v", podName, namespace)
			}
			var v *v1.Deployment
			v, errG = client.Clientset.AppsV1().Deployments(namespace).Get(context.Background(), u.OwnerReferences[0].Name, metav1.GetOptions{})
			if errG != nil {
				return utils.LogLine{
						Objects: objects,
						Error:   errG.Error(),
						Status:  "failure",
					},
					errG
			}
			if v == nil {
				return utils.LogLine{
						Objects: objects,
						Error:   fmt.Sprintf("can't find the deployment for the pod %v in namespace %v", podName, namespace),
						Status:  "failure",
					},
					fmt.Errorf("can't find the deployment for the pod %v in namespace %v", podName, namespace)
			}
			owner = v.ObjectMeta.Name
			labels = v.Spec.Selector.MatchLabels
			if owner == "" || len(labels) == 0 {
				return utils.LogLine{
						Objects: objects,
						Error:   fmt.Sprintf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace),
						Status:  "failure",
					},
					fmt.Errorf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace)
			}
		}
	} else {
		owner = pod.ObjectMeta.Name
		labels = pod.ObjectMeta.Labels
		if owner == "" || len(labels) == 0 {
			return utils.LogLine{
					Objects: objects,
					Error:   fmt.Sprintf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace),
					Status:  "failure",
				},
				fmt.Errorf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace)
		}
	}

	delete(labels, "pod-template-hash")

	payload := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      owner,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{"Egress"},
			PodSelector: metav1.LabelSelector{
				MatchLabels: labels,
			},
		},
	}

	np, err := createEgressRule(action)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	if np != nil {
		payload.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{*np}
	}

	var output string
	_, err = client.NetworkingV1().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		_, err = client.NetworkingV1().NetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		output = fmt.Sprintf("the networkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
	} else {
		_, err = client.NetworkingV1().NetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
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

func createEgressRule(action *rules.Action) (*networkingv1.NetworkPolicyEgressRule, error) {
	if action.GetParameters()["allow"] == nil {
		return nil, nil
	}
	np := make([]networkingv1.NetworkPolicyPeer, 0)
	if allowedCidr := action.GetParameters()["allow"].([]interface{}); len(allowedCidr) != 0 {
		for _, i := range allowedCidr {
			np = append(np,
				networkingv1.NetworkPolicyPeer{
					IPBlock: &networkingv1.IPBlock{
						CIDR: i.(string),
					},
				},
			)
		}
	}
	return &networkingv1.NetworkPolicyEgressRule{To: np}, nil
}

var CheckParameters = func(action *rules.Action) error {
	parameters := action.GetParameters()
	if err := utils.CheckParameters(parameters, "allow", utils.SliceInterfaceStr, nil, false); err != nil {
		return err
	}
	if parameters["allow"] == nil {
		return nil
	}
	if p := parameters["allow"].([]interface{}); len(p) != 0 {
		for _, i := range p {
			if _, _, err := net.ParseCIDR(i.(string)); err != nil {
				return fmt.Errorf("wrong CIDR '%v'", i)
			}
		}
	}
	return nil
}
