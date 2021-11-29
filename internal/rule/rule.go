package rule

import (
	"errors"
	"io/ioutil"
	"log"
	"regexp"
	"strings"

	"github.com/Issif/falco-reactionner/internal/event"
	yaml "gopkg.in/yaml.v3"
)

type Rules []*Rule

type Rule struct {
	Name   string `yaml:"name"`
	Action Action `yaml:"action"`
	Match  Match  `yaml:"match"`
	Weight int    `yaml:"weight"`
}

type Action struct {
	Name    string                 `yaml:"name"`
	Options map[string]interface{} `yaml:"options"`
}

type Match struct {
	PriorityNumber     int
	PriorityComparator string
	Priority           string                 `yaml:"priority"`
	Rules              []string               `yaml:"rules"`
	Source             string                 `yaml:"Source"`
	OutputFields       map[string]interface{} `yaml:"output_fields"`
	Tags               []string               `yaml:"tags"`
}

const (
	Default = iota // ""
	Debug
	Informational
	Notice
	Warning
	Error
	Critical
	Alert
	Emergency
)

var rules *Rules
var priorityCheckRegex *regexp.Regexp
var priorityComparatorRegex *regexp.Regexp

func CreateRules() *Rules {
	yfile, err := ioutil.ReadFile("rules.yaml")
	if err != nil {
		log.Fatalf("%v\n", err.Error())
	}

	err2 := yaml.Unmarshal(yfile, &rules)

	if err2 != nil {
		log.Fatalf("%v\n", err2.Error())
	}

	priorityCheckRegex, _ = regexp.Compile("(?i)^(<|>)?(=)?(Debug|Informational|Notice|Warning|Error|Critical|Alert|Emergency)")
	priorityComparatorRegex, _ = regexp.Compile("^(<|>)?(=)?")

	for _, i := range *rules {
		if i.Name == "" {
			log.Fatalf("[ERROR] All rules must have a name\n", i.Name)
		}
		err := i.SetPriorityNumberComparator()
		if err != nil {
			log.Fatalf("[ERROR] Incorrect Priority for Rule: %v\n", i.Name)
		}
	}

	return rules
}

func (rule *Rule) SetPriorityNumberComparator() error {
	if rule.Match.Priority == "" {
		return nil
	}
	if !priorityCheckRegex.MatchString(rule.Match.Priority) {
		return errors.New("Wrong priority")
	}
	rule.Match.PriorityComparator = priorityComparatorRegex.FindAllString(rule.Match.Priority, -1)[0]
	rule.Match.PriorityNumber = getPriorityNumber(priorityComparatorRegex.ReplaceAllString(rule.Match.Priority, ""))
	return nil
}

func getPriorityNumber(p string) int {
	switch strings.ToLower(p) {
	case "emergency":
		return Emergency
	case "alert":
		return Alert
	case "critical":
		return Critical
	case "error":
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

func GetRules() *Rules {
	return rules
}

func CompareEventToRule(input event.Event, rule Rule) bool {
	if !rulesMatch(input, rule) {
		return false
	}
	if !outputFieldsMatch(input, rule) {
		return false
	}
	return true
}

func rulesMatch(input event.Event, rule Rule) bool {
	if len(rule.Match.Rules) == 0 {
		return true
	}
	for _, i := range rule.Match.Rules {
		if input.Rule == i {
			return true
		}
	}
	return false
}

func outputFieldsMatch(input event.Event, rule Rule) bool {
	if len(rule.Match.OutputFields) == 0 {
		return true
	}
	for i, j := range rule.Match.OutputFields {
		if input.OutputFields[i] == j {
			continue
		}
		return false
	}
	return true
}

func tagsMatch(input event.Event, rule Rule) bool {
	if len(rule.Match.Tags) == 0 {
		return true
	}
	count := 0
	for _, i := range rule.Match.Tags {
		for _, j := range input.Tags {
			if i == j {
				count++
			}
		}
	}
	if count != len(rule.Match.Tags) {
		return false
	}
	return true
}
