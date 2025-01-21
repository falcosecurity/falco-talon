package sysdig

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/falcosecurity/falco-talon/internal/events"
	k8sChecks "github.com/falcosecurity/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "sysdig"
	Category      string = "kubernetes"
	Description   string = "Capture the syscalls packets in a pod"
	Source        string = "syscalls, k8s_audit"
	Continue      bool   = false
	UseContext    bool   = false
	AllowOutput   bool   = false
	RequireOutput bool   = true
	Permissions   string = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: falco-talon
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
  - list
- apiGroups:
  - ""
  resources:
  - pods/exec
  verbs:
  - get
  - create
- apiGroups:
  - "batch"
  resources:
  - jobs
  verbs:
  - get
  - list
  - create
`
	Example string = `- action: Create a syscall capture from a pod
  actionner: kubernetes:sysdig
  parameters:
    duration: 10
    buffer_size: 1024
  output:
    target: aws:s3
    parameters:
      bucket: my-bucket
      prefix: /captures/
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name, k8s.pod.name", "ka.target.namespace, (ka.target.pod.name or ka.target.name)"}
)

type Parameters struct {
	Image      string `mapstructure:"image"`
	Scope      string `mapstructure:"scope" validate:"oneof=pod node"`
	Duration   int    `mapstructure:"duration" validate:"gt=0,lte=30"`
	BufferSize int    `mapstructure:"buffer_size" validate:"gte=128"`
}

const (
	baseName           string = "falco-talon-sysdig-"
	defaultImage       string = "issif/sysdig:latest"
	defaultScope       string = "pod"
	defaultTTL         int    = 60
	defaultDuration    int    = 5
	defaultMaxDuration int    = 30
	defaultBufferSize  int    = 2048
)

type Actionner struct{}

func Register() *Actionner {
	return new(Actionner)
}

func (a Actionner) Init() error {
	return k8s.Init()
}

func (a Actionner) Information() models.Information {
	return models.Information{
		Name:                 Name,
		FullName:             Category + ":" + Name,
		Category:             Category,
		Description:          Description,
		Source:               Source,
		RequiredOutputFields: RequiredOutputFields,
		Permissions:          Permissions,
		Example:              Example,
		Continue:             Continue,
		AllowOutput:          AllowOutput,
		RequireOutput:        RequireOutput,
	}
}

func (a Actionner) Parameters() models.Parameters {
	return Parameters{
		Duration:   defaultDuration,
		Scope:      defaultScope,
		BufferSize: defaultBufferSize,
		Image:      defaultImage,
	}
}

func (a Actionner) Checks(event *events.Event, _ *rules.Action) error {
	return k8sChecks.CheckPodExist(event)
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"pod":       podName,
		"namespace": namespace,
	}

	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	if parameters.Duration == 0 {
		parameters.Duration = defaultDuration
	}

	if parameters.Image == "" {
		parameters.Image = defaultImage
	}

	if parameters.Scope == "" {
		parameters.Scope = defaultScope
	}

	if parameters.BufferSize == 0 {
		parameters.BufferSize = defaultBufferSize
	}

	client := k8s.GetClient()

	pod, _ := client.GetPod(podName, namespace)
	containers := k8s.GetContainers(pod)
	if len(containers) == 0 {
		err = fmt.Errorf("no container found")
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	job, err := client.CreateJob("falco-talon-sysdig", namespace, parameters.Image, pod.Spec.NodeName, defaultTTL)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	objects["job"] = job

	timeout := time.NewTimer(20 * time.Second)
	ticker := time.NewTicker(300 * time.Millisecond)
	defer timeout.Stop()
	defer ticker.Stop()

	var ready bool
	var jPod, jContainer string
	for !ready {
		select {
		case <-timeout.C:
			err = fmt.Errorf("the job '%v' in the namespace '%v' for the sysdig capture is not ready", job, namespace)
			return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			}, nil, err
		case <-ticker.C:
			p, err2 := client.ListPods(metav1.ListOptions{LabelSelector: "batch.kubernetes.io/job-name=" + job})
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				}, nil, err2
			}
			if len(p.Items) > 0 {
				if p.Items[0].Status.Phase == corev1.PodRunning && p.Items[0].Status.ContainerStatuses[0].Ready {
					jPod = p.Items[0].Name
					jContainer = p.Items[0].Spec.Containers[0].Name
					ready = true
				}
			}
		}
	}

	command := []string{"tee", "/tmp/talon-script.sh", "/dev/null"}
	sysdigCmd := fmt.Sprintf("sysdig --modern-bpf --cri /run/containerd/containerd.sock -M %v -s %v -z -w /tmp/sysdig.scap.gz", parameters.Duration, parameters.BufferSize)
	if parameters.Scope == "pod" {
		containers := []string{}
		for _, i := range pod.Status.ContainerStatuses {
			containers = append(containers, strings.ReplaceAll(i.ContainerID, "containerd://", "")[:12])
		}
		sysdigCmd = fmt.Sprintf("%v \"container.id in (%v)\"", sysdigCmd, strings.Join(containers, ","))
	}
	script := fmt.Sprintf("%v || [ $? -eq 0 ] && echo OK || exit 1\n", sysdigCmd)
	_, err = client.Exec(namespace, jPod, jContainer, command, script)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	command = []string{"sh", "/tmp/talon-script.sh"}
	_, err = client.Exec(namespace, jPod, jContainer, command, "")
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	command = []string{"cat", "/tmp/sysdig.scap.gz"}
	output, err := client.Exec(namespace, jPod, jContainer, command, "")
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("a sysdig capture '%v' has been created", "sysdig.scap.gz"),
		Status:  utils.SuccessStr,
	}, &models.Data{Name: "sysdig.scap.gz", Objects: objects, Bytes: output.Bytes()}, nil
}

func (a Actionner) CheckParameters(action *rules.Action) error {
	var parameters Parameters

	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	if parameters.Scope == "" {
		parameters.Scope = defaultScope
	}

	if parameters.BufferSize == 0 {
		parameters.BufferSize = defaultBufferSize
	}

	if parameters.Duration == 0 {
		parameters.Duration = defaultDuration
	}

	err = utils.ValidateStruct(parameters)
	if err != nil {
		return err
	}

	return nil
}
