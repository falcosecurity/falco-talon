package rule

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"

	"github.com/Issif/falco-reactionner/internal/event"
	"github.com/Issif/falco-reactionner/internal/utils"
	yaml "gopkg.in/yaml.v3"
)

// TODO
// allow to set rule by file or CRD
// watch CRD and update rules

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

var rules *Rules
var priorityCheckRegex *regexp.Regexp
var priorityComparatorRegex *regexp.Regexp

func CreateRules() *Rules {
	yamlRulesFile, err := ioutil.ReadFile("rules.yaml")
	if err != nil {
		log.Fatalf("%v\n", err.Error())
	}

	err2 := yaml.Unmarshal(yamlRulesFile, &rules)

	if err2 != nil {
		log.Fatalf("%v\n", err2.Error())
	}

	priorityCheckRegex, _ = regexp.Compile("(?i)^(<|>)?(=)?(Debug|Informational|Notice|Warning|Error|Critical|Alert|Emergency)")
	priorityComparatorRegex, _ = regexp.Compile("^(<|>)?(=)?")

	for _, i := range *rules {
		if i.Name == "" {
			utils.PrintLog("critical", "All rules must have a name")
		}
		err := i.SetPriorityNumberComparator()
		if err != nil {
			utils.PrintLog("critical", fmt.Sprintf("Incorrect Priority for Rule: %v\n", i.Name))
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

func GetRules() *Rules {
	return rules
}

func (rule *Rule) CompareEvent(input *event.Event) bool {
	if !rule.checkRule(input) {
		return false
	}
	if !rule.checkOutputFields(input) {
		return false
	}
	if !rule.checkPriority(input) {
		return false
	}
	// compare to priority
	return true
}

func (rule *Rule) checkRule(input *event.Event) bool {
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

func (rule *Rule) checkOutputFields(input *event.Event) bool {
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

func (rule *Rule) checkTags(input *event.Event) bool {
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

func (rule *Rule) checkPriority(input *event.Event) bool {
	if rule.Match.PriorityNumber == 0 {
		return true
	}
	switch rule.Match.PriorityComparator {
	case ">":
		if getPriorityNumber(input.Priority) > rule.Match.PriorityNumber {
			return true
		}
	case ">=":
		if getPriorityNumber(input.Priority) >= rule.Match.PriorityNumber {
			return true
		}
	case "<":
		if getPriorityNumber(input.Priority) < rule.Match.PriorityNumber {
			return true
		}
	case "<=":
		if getPriorityNumber(input.Priority) <= rule.Match.PriorityNumber {
			return true
		}
	default:
		if getPriorityNumber(input.Priority) == rule.Match.PriorityNumber {
			return true
		}
	}
	return false
}
