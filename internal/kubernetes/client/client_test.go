package kubernetes

import (
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

type targetLookupStub struct {
	getDeploymentCalled bool
	getDaemonSetCalled  bool
}

func (c *targetLookupStub) GetNamespace(string) (*corev1.Namespace, error) {
	return nil, errors.New("not implemented")
}

func (c *targetLookupStub) GetConfigMap(string, string) (*corev1.ConfigMap, error) {
	return nil, errors.New("not implemented")
}

func (c *targetLookupStub) GetSecret(string, string) (*corev1.Secret, error) {
	return nil, errors.New("not implemented")
}

func (c *targetLookupStub) GetDeployment(string, string) (*appsv1.Deployment, error) {
	c.getDeploymentCalled = true
	return nil, errors.New("deployment lookup should not be used")
}

func (c *targetLookupStub) GetDaemonSet(string, string) (*appsv1.DaemonSet, error) {
	c.getDaemonSetCalled = true
	return &appsv1.DaemonSet{}, nil
}

func (c *targetLookupStub) GetStatefulSet(string, string) (*appsv1.StatefulSet, error) {
	return nil, errors.New("not implemented")
}

func (c *targetLookupStub) GetReplicaSet(string, string) (*appsv1.ReplicaSet, error) {
	return nil, errors.New("not implemented")
}

func (c *targetLookupStub) GetService(string, string) (*corev1.Service, error) {
	return nil, errors.New("not implemented")
}

func (c *targetLookupStub) GetServiceAccount(string, string) (*corev1.ServiceAccount, error) {
	return nil, errors.New("not implemented")
}

func (c *targetLookupStub) GetRole(string, string) (*rbacv1.Role, error) {
	return nil, errors.New("not implemented")
}

func (c *targetLookupStub) GetClusterRole(string, string) (*rbacv1.ClusterRole, error) {
	return nil, errors.New("not implemented")
}

func TestLookupTargetUsesDaemonSetLookup(t *testing.T) {
	t.Parallel()

	client := &targetLookupStub{}

	target, err := lookupTarget(client, "daemonsets", "falco-talon", "falco")
	if err != nil {
		t.Fatalf("lookup daemonset target: %v", err)
	}

	if target == nil {
		t.Fatal("expected daemonset target to be returned")
	}

	if !client.getDaemonSetCalled {
		t.Fatal("expected daemonset lookup to be used")
	}

	if client.getDeploymentCalled {
		t.Fatal("did not expect deployment lookup to be used for daemonsets")
	}
}

func TestLookupTargetKeepsDeploymentLookup(t *testing.T) {
	t.Parallel()

	client := &targetLookupStub{}

	_, err := lookupTarget(client, "deployments", "falco-talon", "falco")
	if err == nil {
		t.Fatal("expected deployment stub error")
	}

	if !client.getDeploymentCalled {
		t.Fatal("expected deployment lookup to be used")
	}

	if client.getDaemonSetCalled {
		t.Fatal("did not expect daemonset lookup to be used for deployments")
	}
}
