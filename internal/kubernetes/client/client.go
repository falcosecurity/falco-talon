package kubernetes

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	toolsWatch "k8s.io/client-go/tools/watch"

	klog "k8s.io/klog/v2"

	"github.com/falco-talon/falco-talon/configuration"
	"github.com/falco-talon/falco-talon/utils"
)

type Client struct {
	*k8s.Clientset
	RestConfig *rest.Config
}

var client *Client
var leaseHolderChan chan string

func Init() error {
	if client != nil {
		return nil
	}
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

	// // disable klog
	klog.InitFlags(nil)
	if err := flag.Set("logtostderr", "false"); err != nil {
		return err
	}
	if err := flag.Set("alsologtostderr", "false"); err != nil {
		return err
	}
	flag.Parse()

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

func (client Client) VerifyIfPodWillBeIgnored(parameters map[string]interface{}, pod corev1.Pod, objects map[string]string) (utils.LogLine, error, bool) {

	kind, err := getOwnerKind(pod)
	if err != nil {
		return utils.LogLine{}, err, false
	}

	var result, status string
	var ignore bool

	switch kind {
	case "DaemonSet":
		if ignoreDaemonsets, ok := parameters["ignore_daemonsets"].(bool); ok && ignoreDaemonsets {
			result = fmt.Sprintf("the pod %v in namespace %v belongs to a DaemonSet and will be ignored.", pod.Name, pod.Namespace)
			status = "ignored"
			ignore = true
		}
	case "StatefulSet":
		if ignoreStatefulsets, ok := parameters["ignore_statefulsets"].(bool); ok && ignoreStatefulsets {
			result = fmt.Sprintf("the pod %v in namespace %v belongs to a StatefulSet and will be ignored.", pod.Name, pod.Namespace)
			status = "ignored"
			ignore = true
		}
	case "ReplicaSet":
		return checkReplicaSet(parameters, client, pod, objects)
	}

	if result == "" {
		return utils.LogLine{}, nil, false
	}

	return utils.LogLine{
		Objects: objects,
		Result:  result,
		Status:  status,
	}, nil, ignore
}

func (client Client) GetNode(name string) (*corev1.Node, error) {
	p, err := client.Clientset.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting node '%v': %v", name, err)
	}
	return p, nil
}

func (client Client) GetDeploymentFromPod(pod *corev1.Pod) (*appsv1.Deployment, error) {
	podName := pod.OwnerReferences[0].Name
	namespace := pod.ObjectMeta.Namespace
	r, err := client.GetDeployment(podName, namespace)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the deployment for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetDaemonsetFromPod(pod *corev1.Pod) (*appsv1.DaemonSet, error) {
	podName := pod.OwnerReferences[0].Name
	namespace := pod.ObjectMeta.Namespace
	r, err := client.GetDaemonSet(podName, namespace)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the daemonset for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetStatefulsetFromPod(pod *corev1.Pod) (*appsv1.StatefulSet, error) {
	podName := pod.OwnerReferences[0].Name
	namespace := pod.ObjectMeta.Namespace
	r, err := client.GetStatefulSet(podName, namespace)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the statefulset for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetReplicasetFromPod(pod *corev1.Pod) (*appsv1.ReplicaSet, error) {
	podName := pod.OwnerReferences[0].Name
	namespace := pod.ObjectMeta.Namespace
	r, err := client.GetReplicaSet(podName, namespace)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the replicaset for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetNodeFromPod(pod *corev1.Pod) (*corev1.Node, error) {
	podName := pod.Name
	namespace := pod.ObjectMeta.Namespace
	nodeName := pod.Spec.NodeName
	r, err := client.GetNode(nodeName)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the node for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetTarget(resource, name, namespace string) (interface{}, error) {
	switch resource {
	case "namespaces":
		return client.GetNamespace(name)
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

func (client Client) GetNamespace(name string) (*corev1.Namespace, error) {
	p, err := client.Clientset.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the namespace '%v' doesn't exist", name)
	}
	return p, nil
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

func (client Client) GetWatcherEndpointSlices(labelSelector, namespace string) (<-chan watch.Event, error) {
	watchFunc := func(_ metav1.ListOptions) (watch.Interface, error) {
		timeOut := int64(5)
		return client.DiscoveryV1().EndpointSlices(namespace).Watch(context.Background(), metav1.ListOptions{LabelSelector: labelSelector, TimeoutSeconds: &timeOut})
	}

	watcher, err := toolsWatch.NewRetryWatcher("1", &cache.ListWatch{WatchFunc: watchFunc})
	if err != nil {
		return nil, err
	}
	return watcher.ResultChan(), nil
}

func (client Client) GetLeaseHolder() (<-chan string, error) {
	if leaseHolderChan != nil {
		return leaseHolderChan, nil
	}

	leaseHolderChan = make(chan string, 20)
	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "falco"
	}
	leaderElectionConfig := leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      "falco-talon",
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/part-of": "falco-talon",
					"app.kubernetes.io/name":    "falco-talon",
				},
			},
			Client: client.Clientset.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: *utils.GetLocalIP(),
			},
		},
		LeaseDuration: time.Duration(4) * time.Second,
		RenewDeadline: time.Duration(3) * time.Second,
		RetryPeriod:   time.Duration(2) * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(_ context.Context) {},
			OnStoppedLeading: func() {},
			OnNewLeader: func(identity string) {
				leaseHolderChan <- identity
			},
		},
		ReleaseOnCancel: true,
	}

	leaderElector, err := leaderelection.NewLeaderElector(leaderElectionConfig)
	if err != nil {
		return nil, err
	}

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		leaderElector.Run(ctx)
	}()

	return leaseHolderChan, nil
}

func getOwnerKind(pod corev1.Pod) (string, error) {
	if len(pod.OwnerReferences) == 0 {
		return "", fmt.Errorf("no owner reference found")
	}
	return pod.OwnerReferences[0].Kind, nil
}

func checkReplicaSet(parameters map[string]interface{}, client Client, pod corev1.Pod, objects map[string]string) (utils.LogLine, error, bool) {
	minHealthyParam, ok := parameters["min_healthy_replicas"]
	if !ok {
		return utils.LogLine{}, nil, false
	}

	minHealthy, err := parseMinHealthyReplicas(minHealthyParam)
	if err != nil {
		return utils.LogLine{}, err, false
	}

	replicaset, err := client.GetReplicasetFromPod(&pod)
	if err != nil {
		return utils.LogLine{}, err, false
	}

	healthyReplicas := int64(replicaset.Status.ReadyReplicas)
	if minHealthy > healthyReplicas {
		return utils.LogLine{
			Objects: objects,
			Result:  fmt.Sprintf("Not enough healthy pods: %v required, %v available in ReplicaSet of pod %v in namespace %v.", minHealthy, healthyReplicas, pod.Name, pod.Namespace),
			Status:  "ignored",
		}, nil, true
	}

	return utils.LogLine{}, nil, false
}

func parseMinHealthyReplicas(value interface{}) (int64, error) {
	switch v := value.(type) {
	case string:
		if strings.HasSuffix(v, "%") {
			percentage, err := strconv.ParseInt(strings.TrimSuffix(v, "%"), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid percentage format: %v", err)
			}
			return percentage, nil
		}
		return strconv.ParseInt(v, 10, 64)
	case int, int64:
		return reflect.ValueOf(v).Int(), nil
	default:
		return 0, fmt.Errorf("invalid type for min_healthy_replicas")
	}
}
