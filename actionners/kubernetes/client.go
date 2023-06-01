package kubernetes

import (
	"context"
	"errors"

	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
)

type Client struct {
	*k8s.Clientset
}

var client *Client

var Init = func() error {
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
		return err
	}

	// creates the clientset
	client.Clientset, err = k8s.NewForConfig(k8sconfig)
	if err != nil {
		return err
	}
	return nil
}

func GetClient() *Client {
	return client
}

var CheckPodName = func(event *events.Event) error {
	pod := event.GetPodName()
	if pod == "" {
		return errors.New("missing pod name")
	}
	return nil
}

var CheckNamespace = func(event *events.Event) error {
	namespace := event.GetNamespaceName()
	if namespace == "" {
		return errors.New("missing namespace")
	}
	return nil
}

var CheckPodExist = func(event *events.Event) error {
	if err := CheckPodName(event); err != nil {
		return err
	}
	if err := CheckNamespace(event); err != nil {
		return err
	}

	if _, err := client.GetPod(event.GetPodName(), event.GetNamespaceName()); err == nil {
		return err
	}
	return nil
}

var CheckRemoteIP = func(event *events.Event) error {
	if event.OutputFields["fd.sip"] == nil &&
		event.OutputFields["fd.rip"] == nil {
		return errors.New("missing IP field(s)")
	}
	return nil
}
var CheckRemotePort = func(event *events.Event) error {
	if event.OutputFields["fd.sport"] == nil &&
		event.OutputFields["fd.rport"] == nil {
		return errors.New("missing Port field(s)")
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
