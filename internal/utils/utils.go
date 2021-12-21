package utils

import (
	"log"
	"os"

	"github.com/Issif/falco-talon/internal/event"
)

const (
	errorStr    = "error"
	criticalStr = "critical"
	infoStr     = "info"
)

func PrintLog(level, message string) {
	var prefix string
	switch level {
	case errorStr, criticalStr:
		prefix = "[ERROR]"
	case infoStr:
		prefix = "[INFO]"
	}

	log.Printf("%v %v\n", prefix, message)
	if level == criticalStr {
		os.Exit(1)
	}
}

func ExtractPodAndNamespace(input *event.Event) (pod, namespace string) {
	if input.OutputFields["k8s.ns.name"] != nil && input.OutputFields["k8s.pod.name"] != nil {
		return input.OutputFields["k8s.pod.name"].(string), input.OutputFields["k8s.ns.name"].(string)
	}

	return "", ""
}
