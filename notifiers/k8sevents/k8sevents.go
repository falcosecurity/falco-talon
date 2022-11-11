package k8sevents

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	client "github.com/Issif/falco-talon/actionners/kubernetes"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
)

var Notify = func(rule *rules.Rule, event *events.Event, message, status string) error {
	k8sevent := &corev1.Event{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Event",
			APIVersion: "v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "falco-talon.",
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Namespace: event.GetNamespace(),
			Name:      event.GetPod(),
		},
		Reason:  "falco-talon:" + rule.GetAction(),
		Message: strings.ReplaceAll(message, `'`, `"`),
		Source: corev1.EventSource{
			Component: "falco-talon",
		},
		Type:                corev1.EventTypeNormal,
		EventTime:           metav1.NowMicro(),
		ReportingController: "falcosecurity.org/falco-talon",
		ReportingInstance:   "falco-talon",
		Action:              "falco-talon:" + rule.GetAction(),
	}
	k8sclient := client.GetClient()
	_, err := k8sclient.CoreV1().Events(event.GetNamespace()).Create(context.TODO(), k8sevent, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}
