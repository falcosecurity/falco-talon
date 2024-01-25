package utils

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

const (
	BoolStr           string = "bool"
	FloatStr          string = "float"
	Float64Str        string = "float64"
	StringStr         string = "string"
	IntStr            string = "int"
	Int64Str          string = "int64"
	SliceInterfaceStr string = "[]interface {}"
	MapStringStr      string = "map[string]string"
	MapIntStr         string = "map[string]int"
	MapInterfaceStr   string = "map[string]interface {}"

	errorStr   string = "error"
	warningStr string = "warning"
	fatalStr   string = "fatal"

	textStr  string = "text"
	colorStr string = "color"

	ansiChars string = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
)

type LogLine struct {
	Objects           map[string]string `json:"objects,omitempty"`
	TraceID           string            `json:"trace_id,omitempty"`
	Rule              string            `json:"rule,omitempty"`
	Event             string            `json:"event,omitempty"`
	Message           string            `json:"message,omitempty"`
	Priority          string            `json:"priority,omitempty"`
	Source            string            `json:"source,omitempty"`
	Result            string            `json:"result,omitempty"`
	Notifier          string            `json:"notifier,omitempty"`
	Output            string            `json:"output,omitempty"`
	ActionnerCategory string            `json:"actionner_category,omitempty"`
	Actionner         string            `json:"actionner,omitempty"`
	Action            string            `json:"action,omitempty"`
	Error             string            `json:"error,omitempty"`
	Status            string            `json:"status,omitempty"`
}

func PrintLog(level, format string, line LogLine) {
	// zerolog.TimeFieldFormat = time.RFC3339
	var output zerolog.ConsoleWriter

	var log zerolog.Logger
	f := strings.ToLower(format)
	if f == textStr || f == colorStr {
		output = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		if f != colorStr {
			output.NoColor = true
		}
		output.FormatFieldValue = func(i interface{}) string {
			return fmt.Sprintf("%s", i)
		}
		log = zerolog.New(output).With().Timestamp().Logger()
	} else {
		log = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}

	var l *zerolog.Event
	switch strings.ToLower(level) {
	case warningStr:
		l = log.Warn()
	case errorStr:
		l = log.Error()
	case fatalStr:
		l = log.Fatal()
	default:
		l = log.Info()
	}
	if line.Rule != "" {
		l.Str("rule", line.Rule)
	}
	if line.Event != "" {
		l.Str("event", line.Event)
	}
	if line.Priority != "" {
		l.Str("priority", line.Priority)
	}
	if line.Source != "" {
		l.Str("source", line.Source)
	}
	if line.Notifier != "" {
		l.Str("notifier", line.Notifier)
	}
	if line.Output != "" {
		l.Str("output", line.Output)
	}
	if line.Actionner != "" {
		l.Str("actionner", line.Actionner)
	}
	if line.ActionnerCategory != "" {
		l.Str("actionner_category", line.ActionnerCategory)
	}
	if line.Action != "" {
		l.Str("action", line.Action)
	}
	if line.Status != "" {
		l.Str("status", line.Status)
	}
	if line.Result != "" {
		l.Str("result", line.Result)
	}
	if line.TraceID != "" {
		l.Str("trace_id", line.TraceID)
	}
	if len(line.Objects) > 0 {
		for i, j := range line.Objects {
			l.Str(i, j)
		}
	}
	if line.Error != "" {
		l.Err(errors.New(line.Error))
	}
	if line.Message != "" {
		l.Msg(line.Message)
	}
}

func SetFields(structure interface{}, fields map[string]interface{}) interface{} {
	valueOf := reflect.ValueOf(structure)
	if valueOf.Kind() == reflect.Ptr {
		valueOf = valueOf.Elem()
	}

	for i := 0; i < valueOf.NumField(); i++ {
		fieldType := valueOf.Type().Field(i)
		field := fieldType.Tag.Get("field")
		deflt := fieldType.Tag.Get("default")
		if fields[field] != nil {
			switch valueOf.Type().Field(i).Type.String() {
			case StringStr:
				valueOf.Field(i).SetString(fmt.Sprint(fields[field]))
			case IntStr, Int64Str:
				d := int64(fields[field].(int))
				valueOf.Field(i).SetInt(d)
			case FloatStr, Float64Str:
				valueOf.Field(i).SetFloat(fields[field].(float64))
			case BoolStr:
				valueOf.Field(i).SetBool(fields[field].(bool))
			case MapStringStr:
				valueOf.Field(i).SetMapIndex(reflect.ValueOf(fields[field]), reflect.ValueOf(fields[field]).Elem())
			}
		} else if deflt != "" {
			switch valueOf.Type().Field(i).Type.String() {
			case StringStr:
				valueOf.Field(i).SetString(deflt)
			case IntStr, Int64Str:
				d, _ := strconv.Atoi(deflt)
				valueOf.Field(i).SetInt(int64(d))
			case FloatStr, Float64Str:
				d, _ := strconv.ParseFloat(deflt, 64)
				valueOf.Field(i).SetFloat(d)
			case BoolStr:
				d, _ := strconv.ParseBool(deflt)
				valueOf.Field(i).SetBool(d)
			}
		}
	}

	return structure
}

func CheckParameters(parameters map[string]interface{}, name, typ string, reg *regexp.Regexp, mandatory bool) error {
	if parameters == nil {
		if mandatory {
			return errors.New("missing parameters")
		}
		return nil
	}
	if parameters[name] == nil {
		if mandatory {
			return errors.New("missing parameters")
		}
		return nil
	}
	if reflect.TypeOf(parameters[name]).String() != typ {
		return fmt.Errorf("wrong type for parameter '%v'", name)
	}
	if reg != nil {
		if !reg.Match([]byte(fmt.Sprintf("%v", parameters[name]))) {
			return fmt.Errorf("wrong value for parameter '%v'", name)
		}
	}
	return nil
}

func RemoveSpecialCharacters(input string) string {
	return strings.ReplaceAll(input, "\r\n", "\n")
}

func RemoveAnsiCharacters(str string) string {
	var reg = regexp.MustCompile(ansiChars)
	return reg.ReplaceAllString(str, "")
}
