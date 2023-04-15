package utils

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

const (
	boolStr    = "bool"
	floatStr   = "float"
	float64Str = "float64"
	stringStr  = "string"
	intStr     = "int"
	int64Str   = "int64"

	errorStr = "error"
	fatalStr = "fatal"
	infoStr  = "info"

	textStr  = "text"
	colorStr = "color"
)

type LogLine struct {
	TraceID        string
	Rule           string
	Event          string
	Message        string
	Priority       string
	Source         string
	Notifier       string
	Output         string
	Actionner      string
	Action         string
	ActionCategory string
	Error          error
	Status         string
	Result         string
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
			return strings.ToLower(fmt.Sprintf("%s", i))
		}
		log = zerolog.New(output).With().Timestamp().Logger()
	} else {
		log = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}

	var l *zerolog.Event
	switch strings.ToLower(level) {
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
	if line.Action != "" {
		l.Str("action", line.Action)
	}
	if line.ActionCategory != "" {
		l.Str("action_category", line.ActionCategory)
	}
	if line.Error != nil {
		l.Err(line.Error)
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
			case stringStr:
				valueOf.Field(i).SetString(fields[field].(string))
			case intStr, int64Str:
				d := int64(fields[field].(int))
				valueOf.Field(i).SetInt(d)
			case floatStr, float64Str:
				valueOf.Field(i).SetFloat(fields[field].(float64))
			case boolStr:
				valueOf.Field(i).SetBool(fields[field].(bool))
			}
		} else if deflt != "" {
			switch valueOf.Type().Field(i).Type.String() {
			case stringStr:
				valueOf.Field(i).SetString(deflt)
			case intStr, int64Str:
				d, _ := strconv.Atoi(deflt)
				valueOf.Field(i).SetInt(int64(d))
			case floatStr, float64Str:
				d, _ := strconv.ParseFloat(deflt, 64)
				valueOf.Field(i).SetFloat(d)
			case boolStr:
				d, _ := strconv.ParseBool(deflt)
				valueOf.Field(i).SetBool(d)
			}
		}
	}

	return structure
}
