package rules

import (
	"strings"

	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Default = iota
	Debug
	Informational
	Notice
	Warning
	Error
	Critical
	Alert
	Emergency
)

func getPriorityNumber(priority string) int {
	switch strings.ToLower(priority) {
	case "emergency":
		return Emergency
	case "alert":
		return Alert
	case "critical":
		return Critical
	case utils.ErrorStr:
		return Error
	case "warning":
		return Warning
	case "notice":
		return Notice
	case "informational":
		return Informational
	case "debug":
		return Debug
	default:
		return Default
	}
}
