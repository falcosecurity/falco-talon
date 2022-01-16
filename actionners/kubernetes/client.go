package kubernetes

import (
	"context"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	*k8s.Clientset
}

var client *Client

func init() {
	client = new(Client)
}

func CreateClient() *Client {
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
	return client
}

func GetClient() *Client {
	return client
}

func (client Client) GetPod(pod, namespace string) (*corev1.Pod, error) {
	p, err := client.Clientset.CoreV1().Pods(namespace).Get(context.Background(), pod, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return p, nil
}
