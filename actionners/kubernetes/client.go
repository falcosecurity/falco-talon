package kubernetes

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"
)

type Client struct {
	*k8s.Clientset
}

var client *Client

var Init = func() {
	client = new(Client)
	config := configuration.GetConfiguration()
	var k8sconfig *rest.Config
	var err error
	if config.KubeConfig != "" {
		k8sconfig, err = clientcmd.BuildConfigFromFlags("", config.KubeConfig)
	} else {
		k8sconfig, err = rest.InClusterConfig()
	}
	if err != nil {
		utils.PrintLog("critical", err.Error())
	}

	// creates the clientset
	client.Clientset, err = k8s.NewForConfig(k8sconfig)
	if err != nil {
		utils.PrintLog("critical", err.Error())
	}
}

func GetClient() *Client {
	return client
}

var Check = func(rule *rules.Rule, event *events.Event) error {
	pod := event.GetPod()
	namespace := event.GetNamespace()
	if pod == "" || namespace == "" {
		return errors.New("missing pod or namespace")
	}
	if p := client.GetPod(pod, namespace); p == nil {
		return fmt.Errorf("pod %v in namespace %v doesn't exist (it may have been already terminated)", pod, namespace)
	}
	return nil
}

func (client Client) GetPod(pod, namespace string) *corev1.Pod {
	p, err := client.Clientset.CoreV1().Pods(namespace).Get(context.Background(), pod, metav1.GetOptions{})
	if err != nil {
		return nil
	}
	return p
}
