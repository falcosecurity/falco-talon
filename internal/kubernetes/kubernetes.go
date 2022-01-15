package kubernetes

import (
	"context"
	"encoding/json"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	*k8s.Clientset
}

var client Client

func CreateClient() Client {
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

func GetClient() Client {
	return client
}

func (client Client) GetPod(pod, namespace string) (*corev1.Pod, error) {
	p, err := client.Clientset.CoreV1().Pods(namespace).Get(context.Background(), pod, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return p, nil
}

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

type patch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value,omitempty"`
}

func (client Client) Label(pod, namespace string, labels map[string]string) error {
	payload := make([]patch, 0)
	for i, j := range labels {
		if j == "" {
			continue
		}
		payload = append(payload, patch{
			Op:    "replace",
			Path:  "/metadata/labels/" + i,
			Value: j,
		})
	}
	payloadBytes, _ := json.Marshal(payload)
	_, err := client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), pod, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	if err != nil {
		return err
	}
	payload = make([]patch, 0)
	for i, j := range labels {
		if j != "" {
			continue
		}
		payload = append(payload, patch{
			Op:   "remove",
			Path: "/metadata/labels/" + i,
		})
	}
	payloadBytes, _ = json.Marshal(payload)
	client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), pod, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	return nil
}
