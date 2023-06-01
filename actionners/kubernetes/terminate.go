package kubernetes

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
)

var Terminate = func(rule *rules.Rule, event *events.Event) (string, error) {
	pod := event.GetPodName()
	namespace := event.GetNamespaceName()

	parameters := rule.GetParameters()
	gracePeriodSeconds := new(int64)
	if parameters["gracePeriodSeconds"] != nil {
		*gracePeriodSeconds = int64(parameters["gracePeriodSeconds"].(int))
	}
	err := GetClient().Clientset.CoreV1().Pods(namespace).Delete(context.Background(), pod, metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Pod: '%v' Namespace: '%v' Status: 'terminated'", pod, namespace), err
}
