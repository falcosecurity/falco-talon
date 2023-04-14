package kubernetes

import (
	"context"
	"fmt"
	"strconv"

	v1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
)

var NetworkPolicy = func(rule *rules.Rule, event *events.Event) (string, error) {
	pod := event.GetPod()
	namespace := event.GetNamespace()

	p, err := client.CoreV1().Pods(namespace).Get(context.Background(), pod, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	labels := make(map[string]string)
	var owner string

	if len(p.OwnerReferences) != 0 {
		switch p.OwnerReferences[0].Kind {
		case "DaemonSet":
			var u *v1.DaemonSet
			u, err = client.AppsV1().DaemonSets(namespace).Get(context.Background(), p.OwnerReferences[0].Name, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "StatefulSet":
			var u *v1.StatefulSet
			u, err = client.AppsV1().StatefulSets(namespace).Get(context.Background(), p.OwnerReferences[0].Name, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "ReplicaSet":
			var u *v1.ReplicaSet
			u, err = client.AppsV1().ReplicaSets(namespace).Get(context.Background(), p.OwnerReferences[0].Name, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			var v *v1.Deployment
			v, err = client.AppsV1().Deployments(namespace).Get(context.Background(), u.OwnerReferences[0].Name, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			owner = v.ObjectMeta.Name
			labels = v.Spec.Selector.MatchLabels
		}
	} else {
		owner = p.ObjectMeta.Name
		labels = p.ObjectMeta.Labels
	}

	delete(labels, "pod-template-hash")

	np, err := createEgressRule(event)
	if err != nil {
		return "", err
	}

	var status string
	n, err := client.NetworkingV1().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errors.IsNotFound(err) {
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
	if len(ips) == 0 || len(ports) == 0 {
		return networkingv1.NetworkPolicyEgressRule{}, fmt.Errorf("missing IP or Port field(s)")
	}
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
			k, err := strconv.ParseInt(j.(string), 10, 64)
			if err == nil {
				ports = append(ports, int32(k))
			}
		}
		if i == "fd.rport" {
			k, err := strconv.ParseInt(j.(string), 10, 64)
			if err == nil {
				ports = append(ports, int32(k))
			}
		}
	}
	return ips, ports
}
