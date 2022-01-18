package actionners

import (
	"fmt"

	"github.com/Issif/falco-talon/actionners/kubernetes"
	"github.com/Issif/falco-talon/internal/events"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers"
	"github.com/Issif/falco-talon/utils"
)

type Actionner struct {
	Name     string
	Category string
	Continue bool
	Init     func()
	Check    func(rule *rules.Rule, event *events.Event) error
	Action   func(rule *rules.Rule, event *events.Event) error
}

type Actionners []*Actionner

var actionners *Actionners

func Init() {
	actionners = new(Actionners)
	actionners.Add(
		&Actionner{
			Name:     "terminate",
			Category: "kubernetes",
			Continue: false,
			Init:     kubernetes.Init,
			Check:    kubernetes.Check,
			Action:   kubernetes.Terminate,
		},
		&Actionner{
			Name:     "labelize",
			Category: "kubernetes",
			Continue: true,
			Init:     kubernetes.Init,
			Check:    kubernetes.Check,
			Action:   kubernetes.Labelize,
		})
	categories := map[string]bool{}
	rules := rules.GetRules()
	for _, i := range *rules {
		categories[i.GetActionCategory()] = true
	}
	for _, i := range *GetActionners() {
		if i.Init != nil && categories[i.Category] {
			utils.PrintLog("info", fmt.Sprintf("Init Actionner Category `%v`", i.Category))
			i.Init()
			categories[i.Category] = false
		}
	}
}

func GetActionners() *Actionners {
	return actionners
}

func (actionners *Actionners) GetActionner(category, name string) *Actionner {
	for _, i := range *actionners {
		fmt.Println(i.Name)
		if i.Name == name {
			return i
		}
	}
	return nil
}

func (actionners *Actionners) Add(actionner ...*Actionner) {
	*actionners = append(*actionners, actionner...)
}

func Trigger(rule *rules.Rule, event *events.Event) {
	pod := event.GetPod()
	namespace := event.GetNamespace()
	actionners := GetActionners()
	action := rule.GetAction()
	actionName := rule.GetActionName()
	category := rule.GetActionCategory()
	ruleName := rule.GetName()
	utils.PrintLog("info", fmt.Sprintf("Match - Rule: '%v' Action: '%v' Pod: '%v' Namespace: '%v'", ruleName, action, pod, namespace))
	for _, i := range *actionners {
		if i.Category == category && i.Name == actionName {
			if i.Check != nil {
				if err := i.Check(rule, event); err != nil {
					utils.PrintLog("error", fmt.Sprintf("Action - Rule: '%v' Action: '%v' Pod: '%v' Namespace: '%v' Error: '%v'", ruleName, action, pod, namespace, err.Error()))
					return
				}
			}
			if i.Action(rule, event) != nil {
				notifiers.Notifiy(rule, event, "failure")
			} else {
				notifiers.Notifiy(rule, event, "success")
			}
		}
	}
}
