package kubernetes

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (client Client) Terminate(pod, namespace string, options map[string]interface{}) error {
	gracePeriodSeconds := new(int64)
	if options["gracePeriodSeconds"] != nil {
		*gracePeriodSeconds = int64(options["gracePeriodSeconds"].(int))
	}
	err := client.Clientset.CoreV1().Pods(namespace).Delete(context.Background(), pod, metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds})
	if err != nil {
		return err
	}
	return nil
}
