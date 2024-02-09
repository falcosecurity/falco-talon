package checks

import (
	"errors"

	"github.com/Falco-Talon/falco-talon/internal/events"
	kubernetes "github.com/Falco-Talon/falco-talon/internal/kubernetes/client"
)

func CheckPodName(event *events.Event) error {
	pod := event.GetPodName()
	if pod == "" {
		return errors.New("missing pod name")
	}
	return nil
}

func CheckNamespace(event *events.Event) error {
	namespace := event.GetNamespaceName()
	if namespace == "" {
		return errors.New("missing namespace")
	}
	return nil
}

func CheckPodExist(event *events.Event) error {
	if err := CheckPodName(event); err != nil {
		return err
	}
	if err := CheckNamespace(event); err != nil {
		return err
	}

	client := kubernetes.GetClient()
	if client == nil {
		return errors.New("wrong k8s client")
	}
	_, err := client.GetPod(event.GetPodName(), event.GetNamespaceName())
	return err
}

func CheckTargetName(event *events.Event) error {
	if event.OutputFields["ka.target.name"] == nil {
		return errors.New("missing target name (ka.target.name)")
	}
	return nil
}

func CheckTargetResource(event *events.Event) error {
	if event.OutputFields["ka.target.resource"] == nil {
		return errors.New("missing target resource (ka.target.resource)")
	}
	return nil
}

func CheckTargetNamespace(event *events.Event) error {
	if event.OutputFields["ka.target.namespace"] == nil {
		return errors.New("missing target namespace (ka.target.namespace)")
	}
	return nil
}

func CheckRemoteIP(event *events.Event) error {
	if event.OutputFields["fd.sip"] == nil &&
		event.OutputFields["fd.rip"] == nil {
		return errors.New("missing IP field(s) (fd.sip or fd.rip)")
	}
	return nil
}

func CheckRemotePort(event *events.Event) error {
	if event.OutputFields["fd.sport"] == nil &&
		event.OutputFields["fd.rport"] == nil {
		return errors.New("missing Port field(s) (fd.sport or fd.port)")
	}
	return nil
}

func CheckTargetExist(event *events.Event) error {
	if err := CheckTargetResource(event); err != nil {
		return err
	}
	if err := CheckTargetName(event); err != nil {
		return err
	}
	if err := CheckTargetNamespace(event); err != nil {
		return err
	}

	client := kubernetes.GetClient()
	if client == nil {
		return errors.New("wrong k8s client")
	}
	_, err := client.GetTarget(event.GetTargetResource(), event.GetTargetName(), event.GetTargetNamespace())
	return err
}
