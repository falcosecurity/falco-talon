package checks

import (
	"errors"

	"github.com/Issif/falco-talon/internal/events"
)

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

var CheckRemoteIP = func(event *events.Event) error {
	if event.OutputFields["fd.sip"] == nil &&
		event.OutputFields["fd.rip"] == nil {
		return errors.New("missing IP field(s) (fd.sip or fd.rip)")
	}
	return nil
}
var CheckRemotePort = func(event *events.Event) error {
	if event.OutputFields["fd.sport"] == nil &&
		event.OutputFields["fd.rport"] == nil {
		return errors.New("missing Port field(s) (fd.sport or fd.port)")
	}
	return nil
}
