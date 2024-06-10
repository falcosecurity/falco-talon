package k8sevents

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	textTemplate "text/template"

	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	falcoTalon string = "falco-talon"
	defaultStr string = "default"
)

var plaintextTmpl = `Status: {{ .Status }}
Message: {{ .Message }}
{{- if .Rule }}
Rule: {{ .Rule }}
{{- end }}
{{- if .Action }}
Action: {{ .Action }}
{{- end }}
{{- if .Actionner }}
Actionner: {{ .Actionner }}
{{- end }}
{{- if .Event }}
Event: {{ .Event }}
{{- end }}
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
Output: {{ .Output }}
{{- end }}
{{- if .Target }}
Target: {{ .Target }}
{{- end }}
TraceID: {{ .TraceID }}
`

func Notify(log utils.LogLine) error {
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

	client := kubernetes.GetClient()

	namespace := log.Objects["namespace"]
	ns, err := client.GetNamespace(namespace)
	if err != nil {
		namespace = defaultStr
	}
	if ns == nil {
		namespace = defaultStr
	}

	var reason string
	if log.Actionner != "" {
		reason = log.Actionner
	}
	if log.Target != "" {
		reason = log.Target
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
			Namespace: namespace,
			Name:      log.Objects["pod"],
		},
		Reason:  fmt.Sprintf("%v:%v:%v:%v", falcoTalon, log.Message, reason, log.Status),
		Message: strings.ReplaceAll(message, `'`, `"`),
		Source: corev1.EventSource{
			Component: falcoTalon,
		},
		Type:                corev1.EventTypeNormal,
		EventTime:           metav1.NowMicro(),
		ReportingController: "falcosecurity.org/" + falcoTalon,
		ReportingInstance:   falcoTalon,
		Action:              reason,
	}
	_, err = client.Clientset.CoreV1().Events(namespace).Create(context.TODO(), k8sevent, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}
