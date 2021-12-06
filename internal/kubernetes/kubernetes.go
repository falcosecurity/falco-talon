package kubernetes

import (
	"context"
	"encoding/json"

	"github.com/Issif/falco-reactionner/internal/configuration"
	"github.com/Issif/falco-reactionner/internal/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// TODO
// config for inCluster

type Client struct {
	*k8s.Clientset
}

var client Client

func CreateClient() Client {
	config := configuration.GetConfiguration()
	var k8sconfig *rest.Config
	var err error
	if *config.KubeConfig != "" {
		k8sconfig, err = clientcmd.BuildConfigFromFlags("", *config.KubeConfig)
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

func (client Client) Terminate(pod, namespace string, options map[string]interface{}) error {
	gracePeriodSeconds := new(int64)
	if options["gracePeriodSeconds"] != nil {
		g := int64(options["gracePeriodSeconds"].(int))
		*gracePeriodSeconds = g
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

func (client Client) Label(pod, namespace string, options map[string]interface{}) error {
	payload := []patch{}
	for i, j := range options {
		operation := "replace"
		if j.(string) == "" {
			continue
		}
		payload = append(payload, patch{
			Op:    operation,
			Path:  "/metadata/labels/" + i,
			Value: j.(string),
		})
	}
	payloadBytes, _ := json.Marshal(payload)
	_, err := client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), pod, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	if err != nil {
		return err
	}
	payload = []patch{}
	for i, j := range options {
		operation := "remove"
		if j.(string) != "" {
			continue
		}
		payload = append(payload, patch{
			Op:   operation,
			Path: "/metadata/labels/" + i,
		})
	}
	payloadBytes, _ = json.Marshal(payload)
	client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), pod, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	return nil
}
