package kubernetes

import (
	"context"

	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Issif/falco-talon/actionners/checks"
	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
)

type Client struct {
	*k8s.Clientset
	RestConfig *rest.Config
}

var client *Client

var Init = func() error {
	client = new(Client)
	config := configuration.GetConfiguration()
	var err error
	if config.KubeConfig != "" {
		client.RestConfig, err = clientcmd.BuildConfigFromFlags("", config.KubeConfig)
	} else {
		client.RestConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return err
	}

	// creates the clientset
	client.Clientset, err = k8s.NewForConfig(client.RestConfig)
	if err != nil {
		return err
	}
	return nil
}

func GetClient() *Client {
	return client
}

var CheckPodExist = func(event *events.Event) error {
	if err := checks.CheckPodName(event); err != nil {
		return err
	}
	if err := checks.CheckNamespace(event); err != nil {
		return err
	}

	if _, err := client.GetPod(event.GetPodName(), event.GetNamespaceName()); err == nil {
		return err
	}
	return nil
}

func (client Client) GetPod(pod, namespace string) (*corev1.Pod, error) {
	p, err := client.Clientset.CoreV1().Pods(namespace).Get(context.Background(), pod, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func GetContainers(pod *corev1.Pod) []string {
	c := make([]string, 0)
	for _, i := range pod.Spec.Containers {
		c = append(c, i.Name)
	}
	return c
}

func (client Client) GetDaemonsetFromPod(pod *corev1.Pod) (*v1.DaemonSet, error) {
	d, err := client.Clientset.AppsV1().DaemonSets(pod.ObjectMeta.Namespace).Get(context.Background(), pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (client Client) GetStatefulsetFromPod(pod *corev1.Pod) (*v1.StatefulSet, error) {
	s, err := client.Clientset.AppsV1().StatefulSets(pod.ObjectMeta.Namespace).Get(context.Background(), pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (client Client) GetReplicasetFromPod(pod *corev1.Pod) (*v1.ReplicaSet, error) {
	r, err := client.Clientset.AppsV1().ReplicaSets(pod.ObjectMeta.Namespace).Get(context.Background(), pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (client Client) GetDeloymentFromPod(pod *corev1.Pod) (*v1.ReplicaSet, error) {
	r, err := client.Clientset.AppsV1().ReplicaSets(pod.ObjectMeta.Namespace).Get(context.Background(), pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return r, nil
}
