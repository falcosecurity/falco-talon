package events

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
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

// getOutputFieldString returns the value of the first present output field
// among keys, as a string. Because DecodeEvent uses json.Decoder.UseNumber(),
// non-string fields (e.g. numeric values decoded as json.Number) would panic
// on a bare type assertion; they are formatted with fmt.Sprintf instead.
func (event *Event) getOutputFieldString(keys ...string) string {
	for _, key := range keys {
		v, ok := event.OutputFields[key]
		if !ok || v == nil {
			continue
		}
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func (event *Event) GetPodName() string {
	return event.getOutputFieldString("k8s.pod.name", "ka.target.pod.name", "ka.target.name")
}

func (event *Event) GetNamespaceName() string {
	return event.getOutputFieldString("k8s.ns.name", "ka.target.namespace")
}

func (event *Event) GetHostname() string {
	return event.Hostname
}

func (event *Event) GetTargetName() string {
	return event.getOutputFieldString("ka.target.name")
}

func (event *Event) GetTargetNamespace() string {
	return event.getOutputFieldString("ka.target.namespace")
}

func (event *Event) GetTargetResource() string {
	return event.getOutputFieldString("ka.target.resource")
}

func (event *Event) GetRemoteIP() string {
	return event.getOutputFieldString("fd.rip", "fd.sip")
}

func (event *Event) GetRemotePort() string {
	return event.getOutputFieldString("fd.rport", "fd.sport")
}

func (event *Event) GetRemoteProtocol() string {
	return event.getOutputFieldString("fd.rproto")
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
