package k8sevents

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var Notify = func(rule *rules.Rule, event *events.Event, log utils.LogLine) error {
	if len(log.Message)+len(utils.RemoveSpecialCharacters(log.Output)) > 1022 {
		log.Output = utils.RemoveSpecialCharacters(log.Output)[:1024-len(log.Message)-1]
	}

	fmt.Println(len(log.Output))

	message := fmt.Sprintf("%v\n%v", log.Message, utils.RemoveSpecialCharacters(log.Output))
	if log.Error != nil {
		message += " " + log.Error.Error()
	}

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
			Namespace: event.GetNamespaceName(),
			Name:      event.GetPodName(),
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
	k8sclient := kubernetes.GetClient()
	_, err := k8sclient.CoreV1().Events(event.GetNamespaceName()).Create(context.TODO(), k8sevent, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}
