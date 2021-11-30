package utils

import (
	"log"
	"os"
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
