package actionners

import (
	"github.com/Issif/falco-talon/actionners/kubernetes"
	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers"
	"github.com/Issif/falco-talon/utils"
)

type Actionner struct {
	Init     func() error
	Check    func(rule *rules.Rule, event *events.Event) error
	Action   func(rule *rules.Rule, event *events.Event) (string, error)
	Name     string
	Category string
	Continue bool
}

type category struct {
	initialized bool
	withsuccess bool
}

type Actionners []*Actionner

var actionners *Actionners

func Init() {
	config := configuration.GetConfiguration()
	actionners = new(Actionners)
	a := new(Actionners)
	a.Add(
		&Actionner{
			Name:     "terminate",
			Category: "kubernetes",
			Continue: false,
			Init:     kubernetes.Init,
			Check:    kubernetes.CheckPodNamespace,
			Action:   kubernetes.Terminate,
		},
		&Actionner{
			Name:     "labelize",
			Category: "kubernetes",
			Continue: true,
			Init:     kubernetes.Init,
			Check:    kubernetes.CheckPodNamespace,
			Action:   kubernetes.Labelize,
		},
		&Actionner{
			Name:     "networkpolicy",
			Category: "kubernetes",
			Continue: true,
			Init:     kubernetes.Init,
			Check:    kubernetes.CheckPodNamespace,
			Action:   kubernetes.NetworkPolicy,
		})
	categories := map[string]*category{}
	for _, i := range *a {
		categories[i.Category] = new(category)
	}
	rules := rules.GetRules()
	for _, i := range *a {
		for _, j := range *rules {
			if i.Category == j.GetActionCategory() {
				if !categories[i.Category].initialized {
					categories[i.Category].initialized = true
					if i.Init != nil {
						utils.PrintLog("info", config.LogFormat, utils.LogLine{Message: "init", ActionCategory: i.Category})
						if err := i.Init(); err != nil {
							utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err, ActionCategory: i.Category})
							continue
						}
					}
					categories[i.Category].withsuccess = true
				}
				if categories[i.Category].withsuccess {
					actionners.Add(i)
				}
			}
		}
	}
}

func GetActionners() *Actionners {
	return actionners
}

func (actionners *Actionners) GetActionner(category, name string) *Actionner {
	for _, i := range *actionners {
		if i.Category == category && i.Name == name {
			return i
		}
	}
	return nil
}

func (actionner *Actionner) MustContinue() bool {
	return actionner.Continue
}

func (actionners *Actionners) Add(actionner ...*Actionner) {
	*actionners = append(*actionners, actionner...)
}

func Trigger(rule *rules.Rule, event *events.Event) {
	config := configuration.GetConfiguration()
	actionners := GetActionners()
	action := rule.GetAction()
	actionName := rule.GetActionName()
	category := rule.GetActionCategory()
	ruleName := rule.GetName()
	utils.PrintLog("info", config.LogFormat, utils.LogLine{Message: "match", Rule: ruleName, Action: action})
	for _, i := range *actionners {
		if i.Category == category && i.Name == actionName {
			if i.Check != nil {
				if err := i.Check(rule, event); err != nil {
					utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err, Rule: ruleName, Action: action, TraceID: event.TraceID, Message: "action"})
					return
				}
			}
			if result, err := i.Action(rule, event); err != nil {
				utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err, Rule: ruleName, Action: action, TraceID: event.TraceID, Message: "action"})
				notifiers.NotifiyFailure(rule, event, err.Error())
			} else {
				utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: result, Rule: ruleName, Action: action, TraceID: event.TraceID, Message: "action"})
				notifiers.NotifiySuccess(rule, event, result)
			}
			return
		}
	}
}
