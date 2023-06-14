package k8sevents

import (
	"bytes"
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	textTemplate "text/template"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var plaintextTmpl = `Status: {{ .Status }}
Action: {{ .Action }}
Rule: {{ .Rule }}
Event: {{ .Event }}
Message: {{ .Message }}
{{- if .Pod }}
Pod: {{ .Pod }}
{{- end }}
{{- if .NetworkPolicy }}
NetworkPolicy: {{ .NetworkPolicy }}
{{- end }}
{{- if .Namespace }}
Namespace: {{ .Namespace }}
{{- end }}
{{- if .Error }}
Error: {{ .Error }}
{{- end }}
{{- if .Output }}
Output: 
{{ .Output }}
{{- end }}
`

var Notify = func(rule *rules.Rule, event *events.Event, log utils.LogLine) error {
	var err error
	var message string
	ttmpl := textTemplate.New("message")
	ttmpl, err = ttmpl.Parse(plaintextTmpl)
	if err != nil {
		return err
	}
	var messageBuf bytes.Buffer
	err = ttmpl.Execute(&messageBuf, log)
	if err != nil {
		return err
	}

	message = utils.RemoveSpecialCharacters(messageBuf.String())

	if len(message) > 1024 {
		message = message[:1024]
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
		Reason:  "falco-talon:" + rule.GetAction() + ":" + log.Status,
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
	_, err = k8sclient.CoreV1().Events(event.GetNamespaceName()).Create(context.TODO(), k8sevent, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}
