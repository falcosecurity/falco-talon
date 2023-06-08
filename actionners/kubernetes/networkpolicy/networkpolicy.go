package networkpolicy

import (
	"context"
	"fmt"
	"strconv"

	v1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
)

var NetworkPolicy = func(rule *rules.Rule, event *events.Event) (string, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	client := kubernetes.GetClient()

	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		return "", err
	}

	labels := make(map[string]string)
	var owner string

	if len(pod.OwnerReferences) != 0 {
		switch pod.OwnerReferences[0].Kind {
		case "DaemonSet":
			u, errG := client.GetDaemonsetFromPod(pod)
			if errG != nil {
				return "", errG
			}
			if u == nil {
				return "", fmt.Errorf("can't find the daemonset for the pod %v in namespace %v", podName, namespace)
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
			if owner == "" || len(labels) == 0 {
				return "", fmt.Errorf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace)
			}
		case "StatefulSet":
			u, errG := client.GetStatefulsetFromPod(pod)
			if errG != nil {
				return "", errG
			}
			if u == nil {
				return "", fmt.Errorf("can't find the statefulset for the pod %v in namespace %v", podName, namespace)
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
			if owner == "" || len(labels) == 0 {
				return "", fmt.Errorf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace)
			}
		case "ReplicaSet":
			u, errG := client.GetStatefulsetFromPod(pod)
			if errG != nil {
				return "", errG
			}
			if u == nil {
				return "", fmt.Errorf("can't find the replicaset for the pod %v in namespace %v", podName, namespace)
			}
			var v *v1.Deployment
			v, errG = client.Clientset.AppsV1().Deployments(namespace).Get(context.Background(), u.OwnerReferences[0].Name, metav1.GetOptions{})
			if errG != nil {
				return "", errG
			}
			if v == nil {
				return "", fmt.Errorf("can't find the deployment for the pod %v in namespace %v", podName, namespace)
			}
			owner = v.ObjectMeta.Name
			labels = v.Spec.Selector.MatchLabels
			if owner == "" || len(labels) == 0 {
				return "", fmt.Errorf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace)
			}
		}
	} else {
		owner = pod.ObjectMeta.Name
		labels = pod.ObjectMeta.Labels
		if owner == "" || len(labels) == 0 {
			return "", fmt.Errorf("can't find the owner and/or labels for the pod %v in namespace %v", podName, namespace)
		}
	}

	delete(labels, "pod-template-hash")

	np, err := createEgressRule(event)
	if err != nil {
		return "", err
	}

	var status string
	n, err := client.NetworkingV1().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
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
				Egress: []networkingv1.NetworkPolicyEgressRule{np},
			},
		}
		_, err = client.NetworkingV1().NetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		if err != nil {
			return "", err
		}
		status = "created"
	} else {
		n.Spec.Egress = append(n.Spec.Egress, np)
		_, err = client.NetworkingV1().NetworkPolicies(namespace).Update(context.Background(), n, metav1.UpdateOptions{})
		if err != nil {
			return "", err
		}
		status = "updated"
	}

	return fmt.Sprintf("NetworkPolicy: '%v' Namespace: '%v' Status: '%v'", owner, namespace, status), nil
}

func createEgressRule(event *events.Event) (networkingv1.NetworkPolicyEgressRule, error) {
	ips, ports := extractIPsPorts(event)
	er := networkingv1.NetworkPolicyEgressRule{
		To:    []networkingv1.NetworkPolicyPeer{},
		Ports: []networkingv1.NetworkPolicyPort{},
	}
	for _, i := range ips {
		er.To = append(er.To, networkingv1.NetworkPolicyPeer{
			IPBlock: &networkingv1.IPBlock{
				CIDR: fmt.Sprintf("%v/32", i),
			},
		})
	}
	for _, i := range ports {
		er.Ports = append(er.Ports, networkingv1.NetworkPolicyPort{
			Port: &intstr.IntOrString{
				IntVal: i,
			},
		})
	}
	return er, nil
}

func extractIPsPorts(event *events.Event) ([]string, []int32) {
	ips, ports := []string{}, []int32{}
	for i, j := range event.OutputFields {
		if i == "fd.sip" {
			ips = append(ips, j.(string))
		}
		if i == "fd.rip" {
			ips = append(ips, j.(string))
		}
		if i == "fd.sport" {
			p := fmt.Sprintf("%v", j)
			k, err := strconv.ParseInt(p, 10, 64)
			if err == nil {
				ports = append(ports, int32(k))
			}
		}
		if i == "fd.rport" {
			p := fmt.Sprintf("%v", j)
			k, err := strconv.ParseInt(p, 10, 64)
			if err == nil {
				ports = append(ports, int32(k))
			}
		}
	}
	return ips, ports
}
