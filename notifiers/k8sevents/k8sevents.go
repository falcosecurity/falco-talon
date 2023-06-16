package k8sevents

import (
	"bytes"
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	textTemplate "text/template"

	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/utils"
)

var plaintextTmpl = `Status: {{ .Status }}
Action: {{ .Action }}
Rule: {{ .Rule }}
Event: {{ .Event }}
Message: {{ .Message }}
{{- range $key, $value := .Objects }}
{{ $key }}: {{ $value }}
{{- end }}
{{- if .Error }}
Error: {{ .Error }}
{{- end }}
{{- if .Result }}
Result: {{ .Result }}
{{- end }}
{{- if .Output }}
Output: 
{{ .Output }}
{{- end }}
`

var Notify = func(log utils.LogLine) error {
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
			Namespace: log.Objects["Namespace"],
			Name:      log.Objects["Pod"],
		},
		Reason:  "falco-talon:" + log.Action + ":" + log.Status,
		Message: strings.ReplaceAll(message, `'`, `"`),
		Source: corev1.EventSource{
			Component: "falco-talon",
		},
		Type:                corev1.EventTypeNormal,
		EventTime:           metav1.NowMicro(),
		ReportingController: "falcosecurity.org/falco-talon",
		ReportingInstance:   "falco-talon",
		Action:              "falco-talon:" + log.Action,
	}
	k8sclient := kubernetes.GetClient()
	_, err = k8sclient.CoreV1().Events(log.Objects["Namespace"]).Create(context.TODO(), k8sevent, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}
