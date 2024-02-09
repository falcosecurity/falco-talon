package kubernetes

import (
	"context"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Falco-Talon/falco-talon/configuration"
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

func (client Client) GetPod(pod, namespace string) (*corev1.Pod, error) {
	p, err := client.Clientset.CoreV1().Pods(namespace).Get(context.Background(), pod, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the pod '%v' in the namespace '%v' doesn't exist", pod, namespace)
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

func (client Client) GetDaemonsetFromPod(pod *corev1.Pod) (*appsv1.DaemonSet, error) {
	d, err := client.Clientset.AppsV1().DaemonSets(pod.ObjectMeta.Namespace).Get(context.Background(), pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (client Client) GetStatefulsetFromPod(pod *corev1.Pod) (*appsv1.StatefulSet, error) {
	s, err := client.Clientset.AppsV1().StatefulSets(pod.ObjectMeta.Namespace).Get(context.Background(), pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (client Client) GetReplicasetFromPod(pod *corev1.Pod) (*appsv1.ReplicaSet, error) {
	r, err := client.Clientset.AppsV1().ReplicaSets(pod.ObjectMeta.Namespace).Get(context.Background(), pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (client Client) GetDeloymentFromPod(pod *corev1.Pod) (*appsv1.ReplicaSet, error) {
	r, err := client.Clientset.AppsV1().ReplicaSets(pod.ObjectMeta.Namespace).Get(context.Background(), pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (client Client) GetTarget(resource, name, namespace string) (interface{}, error) {
	switch resource {
	case "configmaps":
		return client.GetConfigMap(name, namespace)
	case "secrets":
		return client.GetSecret(name, namespace)
	case "deployments":
		return client.GetDeployment(name, namespace)
	case "daemonsets":
		return client.GetDeployment(name, namespace)
	case "statefulsets":
		return client.GetStatefulSet(name, namespace)
	case "replicasets":
		return client.GetReplicaSet(name, namespace)
	case "services":
		return client.GetService(name, namespace)
	case "serviceaccounts":
		return client.GetServiceAccount(name, namespace)
	case "roles":
		return client.GetRole(name, namespace)
	case "clusterroles":
		return client.GetClusterRole(name, namespace)
	}

	return nil, errors.New("the resource doesn't exist or its type is not yet managed")
}

func (client Client) GetConfigMap(name, namespace string) (*corev1.ConfigMap, error) {
	p, err := client.Clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the configmap '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetSecret(name, namespace string) (*corev1.Secret, error) {
	p, err := client.Clientset.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the secret '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetDeployment(name, namespace string) (*appsv1.Deployment, error) {
	p, err := client.Clientset.AppsV1().Deployments(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the deployment '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetDaemonSet(name, namespace string) (*appsv1.DaemonSet, error) {
	p, err := client.Clientset.AppsV1().DaemonSets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the daemonset '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetStatefulSet(name, namespace string) (*appsv1.StatefulSet, error) {
	p, err := client.Clientset.AppsV1().StatefulSets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the statefulset '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetReplicaSet(name, namespace string) (*appsv1.ReplicaSet, error) {
	p, err := client.Clientset.AppsV1().ReplicaSets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the replicaset '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetService(name, namespace string) (*corev1.Service, error) {
	p, err := client.Clientset.CoreV1().Services(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the service '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetServiceAccount(name, namespace string) (*corev1.ServiceAccount, error) {
	p, err := client.Clientset.CoreV1().ServiceAccounts(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the serviceaccount '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetRole(name, namespace string) (*rbacv1.Role, error) {
	p, err := client.Clientset.RbacV1().Roles(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the role '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetClusterRole(name, namespace string) (*rbacv1.ClusterRole, error) {
	p, err := client.Clientset.RbacV1().ClusterRoles().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the clusterrole '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}
