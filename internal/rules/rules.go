package rules

import (
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strings"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/utils"
	yaml "gopkg.in/yaml.v3"
)

// TODO
// allow to set rule by file or CRD
// watch CRD and update rules

type Rule struct {
	Name      string   `yaml:"name"`
	Action    Action   `yaml:"action"`
	Match     Match    `yaml:"match"`
	Continue  bool     `yaml:"continue"`
	Notifiers []string `yaml:"notifiers"`
	// Weight   int    `yaml:"weight"`
}

type Action struct {
	Name       string                 `yaml:"name"`
	Arguments  map[string]interface{} `yaml:"arguments,omitempty"`
	Parameters map[string]interface{} `yaml:"parameters,omitempty"`
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

var rules *[]*Rule
var priorityCheckRegex *regexp.Regexp
var actionCheckRegex *regexp.Regexp
var priorityComparatorRegex *regexp.Regexp

func init() {
	priorityCheckRegex, _ = regexp.Compile("(?i)^(<|>)?(=)?(|Debug|Informational|Notice|Warning|Error|Critical|Alert|Emergency)")
	actionCheckRegex, _ = regexp.Compile("[a-z]+:[a-z]+")
	priorityComparatorRegex, _ = regexp.Compile("^(<|>)?(=)?")
}

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

	for _, i := range *rules {
		if i.Name == "" {
			utils.PrintLog("critical", "All rules must have a name")
		}
		if !priorityCheckRegex.MatchString(i.Match.Priority) {
			utils.PrintLog("critical", fmt.Sprintf("Incorrect priority for rule '%v'\n", i.Name))
		}
		if !actionCheckRegex.MatchString(i.Action.Name) {
			utils.PrintLog("critical", fmt.Sprintf("Unknown action for rule '%v'\n", i.Name))
		}
		err := i.setPriorityNumberComparator()
		if err != nil {
			utils.PrintLog("critical", fmt.Sprintf("Incorrect Priority for Rule: %v\n", i.Name))
		}
	}

	return rules
}

func (rule *Rule) setPriorityNumberComparator() error {
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

func (rule *Rule) GetName() string {
	return rule.Name
}

func (rule *Rule) GetAction() string {
	return rule.Action.Name
}

func (rule *Rule) GetActionName() string {
	return strings.Split(rule.Action.Name, ":")[1]
}

func (rule *Rule) GetActionCategory() string {
	return strings.Split(rule.Action.Name, ":")[0]
}

func (rule *Rule) GetParameters() map[string]interface{} {
	return rule.Action.Parameters
}

func (rule *Rule) GetArguments() map[string]interface{} {
	return rule.Action.Arguments
}

func (rule *Rule) MustContinue() bool {
	return rule.Continue
}

func (rule *Rule) CompareRule(event *events.Event) bool {
	if !rule.checkRules(event) {
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
	if !rule.checkSoure(event) {
		return false
	}
	return true
}

func (rule *Rule) checkRules(event *events.Event) bool {
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

func (rule *Rule) checkOutputFields(event *events.Event) bool {
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

func (rule *Rule) checkTags(event *events.Event) bool {
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

func (rule *Rule) checkSoure(event *events.Event) bool {
	if rule.Match.Source == "" {
		return true
	}
	return event.Source == rule.Match.Source
}

func (rule *Rule) checkPriority(event *events.Event) bool {
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
