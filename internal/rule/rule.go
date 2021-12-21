package rule

import (
	"fmt"
	"io/ioutil"
	"log"
	"regexp"

	yaml "gopkg.in/yaml.v3"

	"github.com/Issif/falco-talon/internal/configuration"
	"github.com/Issif/falco-talon/internal/event"
	"github.com/Issif/falco-talon/internal/utils"
)

// TODO
// allow to set rule by file or CRD
// watch CRD and update rules

type Rule struct {
	Action       Action `yaml:"action"`
	Name         string `yaml:"name"`
	Notification string `yaml:"notification"`
	Match        Match  `yaml:"match"`
	Continue     bool   `yaml:"continue"`
	// Weight   int    `yaml:"weight"`
}

type Action struct {
	Options map[string]interface{} `yaml:"options,omitempty"`
	Labels  map[string]string      `yaml:"labels,omitempty"`
	Name    string                 `yaml:"name"`
}

type Match struct {
	OutputFields       map[string]interface{} `yaml:"output_fields"`
	PriorityComparator string
	Priority           string   `yaml:"priority"`
	Source             string   `yaml:"Source"`
	Rules              []string `yaml:"rules"`
	Tags               []string `yaml:"tags"`
	PriorityNumber     int
}

var rules *[]*Rule
var priorityCheckRegex *regexp.Regexp
var ruleCheckRegex *regexp.Regexp
var priorityComparatorRegex *regexp.Regexp

func CreateRules() *[]*Rule {
	config := configuration.GetConfiguration()
	yamlRulesFile, err := ioutil.ReadFile(config.RulesFile)
	if err != nil {
		log.Fatalf("%v\n", err.Error())
	}

	err2 := yaml.Unmarshal(yamlRulesFile, &rules)

	if err2 != nil {
		log.Fatalf("%v\n", err2.Error())
	}

	priorityCheckRegex = regexp.MustCompile("(?i)^(<|>)?(=)?(|Debug|Informational|Notice|Warning|Error|Critical|Alert|Emergency)")
	ruleCheckRegex = regexp.MustCompile("(?i)(terminate|label)")
	priorityComparatorRegex = regexp.MustCompile("^(<|>)?(=)?")

	for _, i := range *rules {
		if i.Name == "" {
			utils.PrintLog("critical", "All rules must have a name")
		}
		if !priorityCheckRegex.MatchString(i.Match.Priority) {
			utils.PrintLog("critical", fmt.Sprintf("Incorrect priority for rule '%v'\n", i.Name))
		}
		if !ruleCheckRegex.MatchString(i.Action.Name) {
			utils.PrintLog("critical", fmt.Sprintf("Unknown action for rule '%v'\n", i.Name))
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
	rule.Match.PriorityComparator = priorityComparatorRegex.FindAllString(rule.Match.Priority, -1)[0]
	rule.Match.PriorityNumber = getPriorityNumber(priorityComparatorRegex.ReplaceAllString(rule.Match.Priority, ""))
	return nil
}

func GetRules() *[]*Rule {
	return rules
}

func (rule *Rule) CompareEvent(event *event.Event) bool {
	if !rule.checkRule(event) {
		return false
	}
	if !rule.checkOutputFields(event) {
		return false
	}
	if !rule.checkPriority(event) {
		return false
	}
	if !rule.checkTags(event) {
		return false
	}
	return true
}

func (rule *Rule) checkRule(event *event.Event) bool {
	if len(rule.Match.Rules) == 0 {
		return true
	}
	for _, i := range rule.Match.Rules {
		if event.Rule == i {
			return true
		}
	}
	return false
}

func (rule *Rule) checkOutputFields(event *event.Event) bool {
	if len(rule.Match.OutputFields) == 0 {
		return true
	}
	for i, j := range rule.Match.OutputFields {
		if event.OutputFields[i] == j {
			continue
		}
		return false
	}
	return true
}

func (rule *Rule) checkTags(event *event.Event) bool {
	if len(rule.Match.Tags) == 0 {
		return true
	}
	count := 0
	for _, i := range rule.Match.Tags {
		for _, j := range event.Tags {
			if i == j {
				count++
			}
		}
	}

	return count == len(rule.Match.Tags)
}

func (rule *Rule) checkPriority(event *event.Event) bool {
	if rule.Match.PriorityNumber == 0 {
		return true
	}
	switch rule.Match.PriorityComparator {
	case ">":
		if getPriorityNumber(event.Priority) > rule.Match.PriorityNumber {
			return true
		}
	case ">=":
		if getPriorityNumber(event.Priority) >= rule.Match.PriorityNumber {
			return true
		}
	case "<":
		if getPriorityNumber(event.Priority) < rule.Match.PriorityNumber {
			return true
		}
	case "<=":
		if getPriorityNumber(event.Priority) <= rule.Match.PriorityNumber {
			return true
		}
	default:
		if getPriorityNumber(event.Priority) == rule.Match.PriorityNumber {
			return true
		}
	}
	return false
}
