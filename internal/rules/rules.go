package rules

import (
	"errors"
	"fmt"
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
	Continue  string   `yaml:"continue"`
	Before    string   `yaml:"before"`
	Match     Match    `yaml:"match"`
	// Weight   int    `yaml:"weight"`
}

type Action struct {
	Arguments  map[string]interface{} `yaml:"arguments,omitempty"`
	Parameters map[string]interface{} `yaml:"parameters,omitempty"`
	Name       string                 `yaml:"name"`
}

type Match struct {
	OutputFields       []string `yaml:"output_fields"`
	OutputFieldsC      [][]outputfield
	PriorityComparator string
	Priority           string   `yaml:"priority"`
	Source             string   `yaml:"Source"`
	Rules              []string `yaml:"rules"`
	Tags               []string `yaml:"tags"`
	TagsC              [][]string
	PriorityNumber     int
}

type outputfield struct {
	Key        string
	Comparator string
	Value      string
}

var rules *[]*Rule
var (
	priorityCheckRegex       *regexp.Regexp
	actionCheckRegex         *regexp.Regexp
	priorityComparatorRegex  *regexp.Regexp
	tagCheckRegex            *regexp.Regexp
	outputFieldKeyCheckRegex *regexp.Regexp
)

func init() {
	priorityCheckRegex = regexp.MustCompile(`(?i)^(<|>)?(=)?(Debug|Informational|Notice|Warning|Error|Critical|Alert|Emergency|)$`)
	actionCheckRegex = regexp.MustCompile(`[a-z]+:[a-z]+`)
	priorityComparatorRegex = regexp.MustCompile(`^(<|>)?(=)?`)
	tagCheckRegex = regexp.MustCompile(`(?i)^[a-z_0-9.]*[a-z0-9]$`)
	outputFieldKeyCheckRegex = regexp.MustCompile(`(?i)^[a-z0-9.\[\]]*(!)?(=)`)
}

func ParseRules(rulesFile string) *[]*Rule {
	config := configuration.GetConfiguration()
	yamlRulesFile, err := os.ReadFile(rulesFile)
	if err != nil {
		utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: err, Message: "rules"})
	}

	err2 := yaml.Unmarshal(yamlRulesFile, &rules)
	if err2 != nil {
		utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err2, Message: "rules"})
		return nil
	}

	for _, i := range *rules {
		for _, j := range i.Match.Tags {
			t := strings.Split(strings.ReplaceAll(j, " ", ""), ",")
			i.Match.TagsC = append(i.Match.TagsC, t)
		}
	}

	for _, i := range *rules {
		for _, j := range i.Match.OutputFields {
			t := strings.Split(strings.ReplaceAll(strings.ReplaceAll(j, "!=", "!"), ", ", ","), ",")
			o := []outputfield{}
			for _, k := range t {
				if strings.Contains(k, "=") {
					p := strings.Split(k, "=")
					if len(p) == 2 {
						o = append(o, outputfield{p[0], "=", strings.ReplaceAll(p[1], `"`, "")})
					}
				}
				if strings.Contains(k, "!") {
					p := strings.Split(k, "!")
					if len(p) == 2 {
						o = append(o, outputfield{p[0], "!=", strings.ReplaceAll(p[1], `"`, "")})
					}
				}
			}
			i.Match.OutputFieldsC = append(i.Match.OutputFieldsC, o)
		}
	}

	invalid := false
	for _, i := range *rules {
		if !i.isValid() {
			invalid = true
		}
	}
	if invalid {
		return nil
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
		utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: fmt.Errorf("incorrect action '%v'", rule.Action.Name), Message: "rules", Rule: rule.Name})
		result = false
	}
	if !priorityCheckRegex.MatchString(rule.Match.Priority) {
		utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: fmt.Errorf("incorrect priority '%v'", rule.Match.Priority), Message: "rules", Rule: rule.Name})
		result = false
	}
	for _, i := range rule.Match.TagsC {
		for _, j := range i {
			if !tagCheckRegex.MatchString(j) {
				utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: fmt.Errorf("incorrect tag '%v'", j), Message: "rules", Rule: rule.Name})
				result = false
			}
		}
	}
	for _, i := range rule.Match.OutputFields {
		t := strings.Split(strings.ReplaceAll(i, ", ", ","), ",")
		for _, j := range t {
			if !outputFieldKeyCheckRegex.MatchString(j) {
				utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: fmt.Errorf("incorrect output field key '%v'", j), Message: "rules", Rule: rule.Name})
				result = false
			}
		}
	}
	if err := rule.setPriorityNumberComparator(); err != nil {
		utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: fmt.Errorf("incorrect priority comparator '%v'", rule.Match.PriorityComparator), Message: "rules", Rule: rule.Name})
		result = false
	}
	if rule.Continue == "false" && rule.Before == "true" {
		utils.PrintLog("warning", config.LogFormat, utils.LogLine{Error: errors.New("if before=true, continue=false is ignored"), Message: "rules", Rule: rule.Name})
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
	for _, i := range rule.Match.OutputFieldsC {
		var countK, countV, countF int
		for _, j := range i {
			if j.Comparator == "=" {
				countK++
			}
		}
		for _, j := range i {
			for k, v := range event.OutputFields {
				if j.Comparator == "!=" && j.Key == k && j.Value == fmt.Sprintf("%v", v) {
					countF++
				}
				if j.Comparator == "=" && j.Key == k && j.Value == fmt.Sprintf("%v", v) {
					countV++
				}
			}
		}
		if countK == countV && countF == 0 {
			return true
		}
	}
	return false
}

func (rule *Rule) compareTags(event *events.Event) bool {
	if len(rule.Match.TagsC) == 0 {
		return true
	}
	for _, i := range rule.Match.TagsC {
		count := 0
		for _, j := range i {
			for _, k := range event.Tags {
				if k == j {
					count++
				}
			}
		}
		if count == len(i) {
			return true
		}
	}
	return false
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
