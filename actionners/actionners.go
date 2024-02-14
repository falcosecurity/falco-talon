package actionners

import (
	"fmt"

	calicoNetworkpolicy "github.com/Falco-Talon/falco-talon/actionners/calico/networkpolicy"
	k8sDelete "github.com/Falco-Talon/falco-talon/actionners/kubernetes/delete"
	k8sExec "github.com/Falco-Talon/falco-talon/actionners/kubernetes/exec"
	k8sLabelize "github.com/Falco-Talon/falco-talon/actionners/kubernetes/labelize"
	k8sLog "github.com/Falco-Talon/falco-talon/actionners/kubernetes/log"
	k8sNetworkpolicy "github.com/Falco-Talon/falco-talon/actionners/kubernetes/networkpolicy"
	k8sScript "github.com/Falco-Talon/falco-talon/actionners/kubernetes/script"
	k8sTerminate "github.com/Falco-Talon/falco-talon/actionners/kubernetes/terminate"
	"github.com/Falco-Talon/falco-talon/configuration"
	calico "github.com/Falco-Talon/falco-talon/internal/calico/client"
	"github.com/Falco-Talon/falco-talon/internal/events"
	k8sChecks "github.com/Falco-Talon/falco-talon/internal/kubernetes/checks"
	k8s "github.com/Falco-Talon/falco-talon/internal/kubernetes/client"
	"github.com/Falco-Talon/falco-talon/internal/rules"
	"github.com/Falco-Talon/falco-talon/metrics"
	"github.com/Falco-Talon/falco-talon/notifiers"
	"github.com/Falco-Talon/falco-talon/utils"
)

type Actionner struct {
	Name            string
	Category        string
	Action          func(action *rules.Action, event *events.Event) (utils.LogLine, error)
	CheckParameters func(action *rules.Action) error
	Init            func() error
	Checks          []checkActionner
	DefaultContinue bool
}

type checkActionner func(event *events.Event) error

type Actionners []*Actionner

var availableActionners *Actionners
var enabledActionners *Actionners

const (
	trueStr  string = "true"
	falseStr string = "false"
)

func init() {
	availableActionners = new(Actionners)
	availableActionners = GetDefaultActionners()
	enabledActionners = new(Actionners)
}

func GetDefaultActionners() *Actionners {
	if len(*availableActionners) == 0 {
		availableActionners.Add(
			&Actionner{
				Category:        "kubernetes",
				Name:            "terminate",
				DefaultContinue: false,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: k8sTerminate.CheckParameters,
				Action:          k8sTerminate.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "labelize",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks:          []checkActionner{k8sChecks.CheckPodExist},
				CheckParameters: k8sLabelize.CheckParameters,
				Action:          k8sLabelize.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "networkpolicy",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: k8sNetworkpolicy.CheckParameters,
				Action:          k8sNetworkpolicy.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "exec",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: k8sExec.CheckParameters,
				Action:          k8sExec.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "script",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: k8sScript.CheckParameters,
				Action:          k8sScript.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "log",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: k8sLog.CheckParameters,
				Action:          k8sLog.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "delete",
				DefaultContinue: false,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: nil,
				Action:          k8sDelete.Action,
			},
			&Actionner{
				Category:        "calico",
				Name:            "networkpolicy",
				DefaultContinue: false,
				Init:            calico.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
					k8sChecks.CheckRemoteIP,
				},
				CheckParameters: calicoNetworkpolicy.CheckParameters,
				Action:          calicoNetworkpolicy.Action,
			},
		)
	}

	return availableActionners
}

func Init() error {
	config := configuration.GetConfiguration()
	rules := rules.GetRules()

	categories := map[string]bool{}
	enabledCategories := map[string]bool{}

	// list actionner categories to init
	for _, i := range *rules {
		for _, j := range i.Actions {
			categories[j.GetActionnerCategory()] = true
		}
	}

	for category := range categories {
		for _, actionner := range *availableActionners {
			if category == actionner.Category {
				if actionner.Init != nil {
					utils.PrintLog("info", config.LogFormat, utils.LogLine{Message: "init", ActionnerCategory: actionner.Category})
					if err := actionner.Init(); err != nil {
						utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err.Error(), ActionnerCategory: actionner.Category})
						return err
					}
					enabledCategories[category] = true
				}
				break // we break to avoid to repeat the same init() several times
			}
		}
	}

	for i := range enabledCategories {
		for _, j := range *availableActionners {
			if i == j.Category {
				enabledActionners.Add(j)
			}
		}
	}

	return nil
}

func (actionners *Actionners) Add(actionner ...*Actionner) {
	*actionners = append(*actionners, actionner...)
}

func GetActionners() *Actionners {
	return enabledActionners
}

func (actionners *Actionners) FindActionner(fullname string) *Actionner {
	if actionners == nil {
		return nil
	}

	for _, i := range *actionners {
		if i == nil {
			continue
		}
		if fullname == fmt.Sprintf("%v:%v", i.Category, i.Name) {
			return i
		}
	}
	return nil
}

func (actionner *Actionner) GetFullName() string {
	return actionner.Category + ":" + actionner.Name
}

func (actionner *Actionner) GetName() string {
	return actionner.Name
}

func (actionner *Actionner) GetCategory() string {
	return actionner.Category
}

func (actionner *Actionner) MustDefaultContinue() bool {
	return actionner.DefaultContinue
}

func RunAction(rule *rules.Rule, action *rules.Action, event *events.Event) error {
	config := configuration.GetConfiguration()
	actionners := GetActionners()
	if actionners == nil {
		return nil
	}

	log := utils.LogLine{
		Message:   "action",
		Rule:      rule.GetName(),
		Event:     event.Output,
		Action:    action.GetName(),
		Actionner: action.GetActionner(),
		TraceID:   event.TraceID,
	}

	if rule.DryRun == trueStr {
		log.Output = "no action, dry-run is enabled"
		utils.PrintLog("info", config.LogFormat, log)
		return nil
	}

	actionner := actionners.FindActionner(action.GetActionner())
	if actionner == nil {
		log.Error = fmt.Sprintf("unknown actionner '%v'", action.GetActionner())
		utils.PrintLog("error", config.LogFormat, log)
		return fmt.Errorf("unknown actionner '%v'", action.GetActionner())
	}

	if checks := actionner.Checks; len(checks) != 0 {
		for _, i := range checks {
			if err := i(event); err != nil {
				log.Error = err.Error()
				utils.PrintLog("error", config.LogFormat, log)
				return err
			}
		}
	}

	result, err := actionner.Action(action, event)
	log.Status = result.Status
	if len(result.Objects) != 0 {
		log.Objects = result.Objects
	}
	if result.Output != "" {
		log.Output = result.Output
	}
	if result.Error != "" {
		log.Error = result.Error
	}

	metrics.IncreaseCounter(log)

	if err != nil {
		utils.PrintLog("error", config.LogFormat, log)
		notifiers.Notify(rule, action, event, log)
		return err
	}
	utils.PrintLog("info", config.LogFormat, log)
	notifiers.Notify(rule, action, event, log)
	return nil
}
