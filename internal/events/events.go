package events

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Event struct {
	TraceID      string         `json:"trace_id"`
	Output       string         `json:"output"`
	Priority     string         `json:"priority"`
	Rule         string         `json:"rule"`
	Hostname     string         `json:"hostname"`
	Time         time.Time      `json:"time"`
	Source       string         `json:"source"`
	OutputFields map[string]any `json:"output_fields"`
	Context      map[string]any `json:"context"`
	Tags         []any          `json:"tags"`
}

const (
	trimPrefix = "(?i)^\\d{2}:\\d{2}:\\d{2}\\.\\d{9}\\:\\ (Debug|Info|Informational|Notice|Warning|Error|Critical|Alert|Emergency)"
)

var regTrimPrefix *regexp.Regexp

func init() {
	regTrimPrefix = regexp.MustCompile(trimPrefix)
}

func DecodeEvent(payload io.Reader) (*Event, error) {
	var event Event

	d := json.NewDecoder(payload)
	d.UseNumber()

	err := d.Decode(&event)
	if err != nil {
		return &Event{}, err
	}

	if event.Source == "" {
		event.Source = "syscall"
	}

	event.Output = regTrimPrefix.ReplaceAllString(event.Output, "")
	event.Output = strings.TrimPrefix(event.Output, " ")

	return &event, nil
}

// outputFieldAsString returns the value stored at key in OutputFields as a
// string. OutputFields is decoded straight from the alert JSON, so a value can
// be any type, and Falco sends some fields (the ports) as numbers. It reports
// false when the key is absent, nil, or holds a type with no string form, so
// callers fall through instead of asserting on the value and panicking on a
// non-string. Numbers arrive as json.Number (handler decode, UseNumber) or
// float64 (consumer decode, plain json.Unmarshal); both are kept.
func (event *Event) outputFieldAsString(key string) (string, bool) {
	switch v := event.OutputFields[key].(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	default:
		return "", false
	}
}

func (event *Event) GetPodName() string {
	if v, ok := event.outputFieldAsString("k8s.pod.name"); ok {
		return v
	}
	if v, ok := event.outputFieldAsString("ka.target.pod.name"); ok {
		return v
	}
	if v, ok := event.outputFieldAsString("ka.target.name"); ok {
		return v
	}
	return ""
}

func (event *Event) GetNamespaceName() string {
	if v, ok := event.outputFieldAsString("k8s.ns.name"); ok {
		return v
	}
	if v, ok := event.outputFieldAsString("ka.target.namespace"); ok {
		return v
	}
	return ""
}

func (event *Event) GetHostname() string {
	return event.Hostname
}

func (event *Event) GetTargetName() string {
	if v, ok := event.outputFieldAsString("ka.target.name"); ok {
		return v
	}
	return ""
}

func (event *Event) GetTargetNamespace() string {
	if v, ok := event.outputFieldAsString("ka.target.namespace"); ok {
		return v
	}
	return ""
}

func (event *Event) GetTargetResource() string {
	if v, ok := event.outputFieldAsString("ka.target.resource"); ok {
		return v
	}
	return ""
}

func (event *Event) GetRemoteIP() string {
	if v, ok := event.outputFieldAsString("fd.rip"); ok {
		return v
	}
	if v, ok := event.outputFieldAsString("fd.sip"); ok {
		return v
	}
	return ""
}

func (event *Event) GetRemotePort() string {
	if v, ok := event.outputFieldAsString("fd.rport"); ok {
		return v
	}
	if v, ok := event.outputFieldAsString("fd.sport"); ok {
		return v
	}
	return ""
}

func (event *Event) GetRemoteProtocol() string {
	if v, ok := event.outputFieldAsString("fd.rproto"); ok {
		return v
	}
	if v, ok := event.outputFieldAsString("fd.sproto"); ok {
		return v
	}
	return ""
}

func (event *Event) AddContext(elements map[string]any) {
	if event.Context == nil {
		event.Context = make(map[string]any)
	}
	if len(elements) == 0 {
		return
	}
	for i, j := range elements {
		if fmt.Sprintf("%v", j) == "" {
			delete(elements, i)
		}
	}
	for i, j := range elements {
		event.Context[i] = j
	}
}

func (event *Event) ExportEnvVars() {
	for i, j := range event.OutputFields {
		key := strings.ReplaceAll(strings.ToUpper(i), ".", "_")
		key = strings.ReplaceAll(key, "[", "_")
		key = strings.ReplaceAll(key, "]", "")
		os.Setenv(key, fmt.Sprintf("%v", j))
	}
	for i, j := range event.Context {
		key := strings.ReplaceAll(strings.ToUpper(i), ".", "_")
		os.Setenv(key, fmt.Sprintf("%v", j))
	}
	os.Setenv("PRIORITY", event.Priority)
	os.Setenv("HOSTNAME", event.Hostname)
	os.Setenv("RULE", event.Rule)
	os.Setenv("SOURCE", event.Source)
	var tags []string
	for _, i := range event.Tags {
		tags = append(tags, fmt.Sprintf("%v", i))
	}
	os.Setenv("TAGS", strings.Join(tags, ","))
}

func (event *Event) String() string {
	e, _ := json.Marshal(*event)
	return string(e)
}
