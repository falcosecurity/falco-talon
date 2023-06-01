package rules

import (
	"errors"
	"os"
	"regexp"
	"strings"

	yaml "gopkg.in/yaml.v3"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/utils"
)

// TODO
// allow to set rule by file or CRD
// watch CRD and update rules

type Rule struct {
	Notifiers []string `yaml:"notifiers"`
	Action    Action   `yaml:"action"`
	Name      string   `yaml:"name"`
	Match     Match    `yaml:"match"`
	Continue  string   `yaml:"continue"`
	// Weight   int    `yaml:"weight"`
}

type Action struct {
	Arguments  map[string]interface{} `yaml:"arguments,omitempty"`
	Parameters map[string]interface{} `yaml:"parameters,omitempty"`
	Name       string                 `yaml:"name"`
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
var actionCheckRegex *regexp.Regexp
var priorityComparatorRegex *regexp.Regexp

func init() {
	priorityCheckRegex = regexp.MustCompile("(?i)^(<|>)?(=)?(|Debug|Informational|Notice|Warning|Error|Critical|Alert|Emergency)")
	actionCheckRegex = regexp.MustCompile("[a-z]+:[a-z]+")
	priorityComparatorRegex = regexp.MustCompile("^(<|>)?(=)?")
}

func ParseRules() *[]*Rule {
	config := configuration.GetConfiguration()
	yamlRulesFile, err := os.ReadFile(config.RulesFile)
	if err != nil {
		utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: err, Message: "rules"})
	}

	err2 := yaml.Unmarshal(yamlRulesFile, &rules)
	if err2 != nil {
		utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err2, Message: "rules"})
		return nil
	}

	for _, i := range *rules {
		invalid := false
		if !i.isValid() {
			invalid = true
		}
		if invalid {
			return nil
		}
	}

	return rules
}

func (rule *Rule) isValid() bool {
	config := configuration.GetConfiguration()
	result := true
	if rule.Name == "" {
		utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: errors.New("all rules must have a name"), Message: "rules"})
		result = false
	}
	if !actionCheckRegex.MatchString(rule.Action.Name) {
		utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: errors.New("unknown action"), Message: "rules", Rule: rule.Name})
		result = false
	}
	if !priorityCheckRegex.MatchString(rule.Match.Priority) {
		utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: errors.New("incorrect priority"), Message: "rules", Rule: rule.Name})
		result = false
	}
	if err := rule.setPriorityNumberComparator(); err != nil {
		utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: errors.New("incorrect priority comparator"), Message: "rules", Rule: rule.Name})
		result = false
	}
	return result
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
	return strings.ToLower(rule.Action.Name)
}

func (rule *Rule) GetActionName() string {
	return strings.ToLower(strings.Split(rule.Action.Name, ":")[1])
}

func (rule *Rule) GetActionCategory() string {
	return strings.ToLower(strings.Split(rule.Action.Name, ":")[0])
}

func (rule *Rule) GetParameters() map[string]interface{} {
	return rule.Action.Parameters
}

func (rule *Rule) GetArguments() map[string]interface{} {
	return rule.Action.Arguments
}

func (rule *Rule) GetNotifiers() []string {
	return rule.Notifiers
}

// func (rule *Rule) MustContinue() bool {
// 	return strings.ToLower(rule.Continue) == "true"
// }

func (rule *Rule) CompareRule(event *events.Event) bool {
	if !rule.findRules(event) {
		return false
	}
	if !rule.compareOutputFields(event) {
		return false
	}
	if !rule.comparePriority(event) {
		return false
	}
	if !rule.compareTags(event) {
		return false
	}
	if !rule.compareSoure(event) {
		return false
	}
	return true
}

func (rule *Rule) findRules(event *events.Event) bool {
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

func (rule *Rule) compareOutputFields(event *events.Event) bool {
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

func (rule *Rule) compareTags(event *events.Event) bool {
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

func (rule *Rule) compareSoure(event *events.Event) bool {
	if rule.Match.Source == "" {
		return true
	}
	return event.Source == rule.Match.Source
}

func (rule *Rule) comparePriority(event *events.Event) bool {
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
