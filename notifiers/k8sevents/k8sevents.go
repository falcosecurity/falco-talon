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

const (
	falcoTalon = "falco-talon"
)

var plaintextTmpl = `Status: {{ .Status }}
Message: {{ .Message }}
Rule: {{ .Rule }}
Action: {{ .Action }}
Actionner: {{ .Actionner }}
Event: {{ .Event }}
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
TraceID: {{ .TraceID }}
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
			GenerateName: falcoTalon + "-",
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Namespace: log.Objects["Namespace"],
			Name:      log.Objects["Pod"],
		},
		Reason:  falcoTalon + ":" + log.Actionner + ":" + log.Status,
		Message: strings.ReplaceAll(message, `'`, `"`),
		Source: corev1.EventSource{
			Component: falcoTalon,
		},
		Type:                corev1.EventTypeNormal,
		EventTime:           metav1.NowMicro(),
		ReportingController: "falcosecurity.org/" + falcoTalon,
		ReportingInstance:   falcoTalon,
		Action:              log.Actionner,
	}
	k8sclient := kubernetes.GetClient()
	_, err = k8sclient.CoreV1().Events(log.Objects["Namespace"]).Create(context.TODO(), k8sevent, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}
