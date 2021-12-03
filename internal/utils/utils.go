package utils

import (
	"log"
	"os"

	"github.com/Issif/falco-reactionner/internal/event"
)

// TODO
// better logs

func PrintLog(level, message string) {
	var prefix string
	switch level {
	case "error", "critical":
		prefix = "[ERROR] "
	case "info":
		prefix = "[INFO] "
	}
	log.Printf("%v %v\n", prefix, message)
	if level == "critical" {
		os.Exit(1)
	}
}

func ExtractPodAndNamespace(input *event.Event) (pod, namespace string) {
	if input.OutputFields["k8s.ns.name"] != nil && input.OutputFields["k8s.pod.name"] != nil {
		return input.OutputFields["k8s.pod.name"].(string), input.OutputFields["k8s.ns.name"].(string)
	}
	return "", ""
}
