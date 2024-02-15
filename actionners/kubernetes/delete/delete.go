package networkpolicy

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Falco-Talon/falco-talon/internal/events"
	kubernetes "github.com/Falco-Talon/falco-talon/internal/kubernetes/client"
	"github.com/Falco-Talon/falco-talon/internal/rules"
	"github.com/Falco-Talon/falco-talon/utils"
)

const namespaces string = "namespaces"

func Action(_ *rules.Action, event *events.Event) (utils.LogLine, error) {
	name := event.GetTargetName()
	resource := event.GetTargetResource()
	namespace := event.GetTargetNamespace()

	objects := map[string]string{
		"name":      name,
		"resource":  resource,
		"namespace": namespace,
	}

	client := kubernetes.GetClient()

	var err error

	switch resource {
	case namespaces:
		err = client.Clientset.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
	case "configmaps":
		err = client.Clientset.CoreV1().ConfigMaps(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "secrets":
		err = client.Clientset.CoreV1().Secrets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "deployments":
		err = client.Clientset.AppsV1().Deployments(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "daemonsets":
		err = client.Clientset.AppsV1().DaemonSets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "statefulsets":
		err = client.Clientset.AppsV1().StatefulSets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "replicasets":
		err = client.Clientset.AppsV1().ReplicaSets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "services":
		err = client.Clientset.CoreV1().Services(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "serviceaccounts":
		err = client.Clientset.CoreV1().ServiceAccounts(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "roles":
		err = client.Clientset.RbacV1().Roles(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "clusterroles":
		err = client.Clientset.RbacV1().ClusterRoles().Delete(context.Background(), name, metav1.DeleteOptions{})
	}

	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	var output string
	if resource == namespaces {
		output = fmt.Sprintf("the %v '%v' has been deleted", strings.TrimSuffix(resource, "s"), name)
	} else {
		output = fmt.Sprintf("the %v '%v' in the namespace '%v' has been deleted", strings.TrimSuffix(resource, "s"), name, namespace)
	}

	return utils.LogLine{
			Objects: objects,
			Output:  output,
			Status:  "success",
		},
		nil
}
