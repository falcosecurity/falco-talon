package terminate

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

var Terminate = func(rule *rules.Rule, event *events.Event) (utils.LogLine, error) {
	pod := event.GetPodName()
	namespace := event.GetNamespaceName()

	parameters := rule.GetParameters()
	gracePeriodSeconds := new(int64)
	if parameters["gracePeriodSeconds"] != nil {
		*gracePeriodSeconds = int64(parameters["gracePeriodSeconds"].(int))
	}

	client := kubernetes.GetClient()

	err := client.Clientset.CoreV1().Pods(namespace).Delete(context.Background(), pod, metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds})
	if err != nil {
		return utils.LogLine{
				Pod:       pod,
				Namespace: namespace,
				Status:    "failure",
				Error:     err,
			},
			err
	}
	return utils.LogLine{
			Pod:       pod,
			Namespace: namespace,
			Status:    "success",
		},
		nil
}

var CheckParameters = func(rule *rules.Rule) error {
	parameters := rule.GetParameters()
	return utils.CheckParameters(parameters, "gracePeriodSeconds", utils.IntStr)
}
