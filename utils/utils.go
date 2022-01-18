package utils

import (
	"log"
	"os"
	"reflect"
	"strconv"
)

func PrintLog(level, message string) {
	var prefix string
	switch level {
	case "error", "critical":
		prefix = "[ERROR]"
	case "info":
		prefix = "[INFO] "
	}
	log.Printf("%v %v\n", prefix, message)
	if level == "critical" {
		os.Exit(1)
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
			case "string":
				valueOf.Field(i).SetString(fields[field].(string))
			case "int", "int64":
				d := int64(fields[field].(int))
				valueOf.Field(i).SetInt(d)
			case "float", "float64":
				valueOf.Field(i).SetFloat(fields[field].(float64))
			case "bool":
				valueOf.Field(i).SetBool(fields[field].(bool))
			}
		} else if deflt != "" {
			switch valueOf.Type().Field(i).Type.String() {
			case "string":
				valueOf.Field(i).SetString(deflt)
			case "int", "int64":
				d, _ := strconv.Atoi(deflt)
				valueOf.Field(i).SetInt(int64(d))
			case "float", "float64":
				d, _ := strconv.ParseFloat(deflt, 64)
				valueOf.Field(i).SetFloat(d)
			case "bool":
				d, _ := strconv.ParseBool(deflt)
				valueOf.Field(i).SetBool(d)
			}
		}
	}
	return structure
}
