package actionners

import (
	"fmt"

	"github.com/Issif/falco-talon/actionners/kubernetes/exec"
	labelize "github.com/Issif/falco-talon/actionners/kubernetes/labelize"
	logActionner "github.com/Issif/falco-talon/actionners/kubernetes/log"
	networkpolicy "github.com/Issif/falco-talon/actionners/kubernetes/networkpolicy"
	"github.com/Issif/falco-talon/actionners/kubernetes/script"
	terminate "github.com/Issif/falco-talon/actionners/kubernetes/terminate"
	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/events"
	kubernetes "github.com/Issif/falco-talon/internal/kubernetes/client"
	"github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers"
	"github.com/Issif/falco-talon/utils"
)

type Actionner struct {
	Name            string
	Category        string
	Action          func(rule *rules.Rule, action *rules.Action, event *events.Event) (utils.LogLine, error)
	CheckParameters func(action *rules.Action) error
	Init            func() error
	Checks          []checkActionner
	DefaultContinue bool
}

type checkActionner func(event *events.Event) error

type Actionners []*Actionner

var defaultActionners *Actionners
var enabledActionners *Actionners

const (
	trueStr  string = "true"
	falseStr string = "false"
)

func init() {
	defaultActionners = new(Actionners)
	defaultActionners = GetDefaultActionners()
	enabledActionners = new(Actionners)
}

func GetDefaultActionners() *Actionners {
	if len(*defaultActionners) == 0 {
		defaultActionners.Add(
			&Actionner{
				Category:        "kubernetes",
				Name:            "terminate",
				DefaultContinue: false,
				Init:            kubernetes.Init,
				Checks:          []checkActionner{kubernetes.CheckPodExist},
				CheckParameters: terminate.CheckParameters,
				Action:          terminate.Terminate,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "labelize",
				DefaultContinue: true,
				Init:            kubernetes.Init,
				Checks:          []checkActionner{kubernetes.CheckPodExist},
				CheckParameters: labelize.CheckParameters,
				Action:          labelize.Labelize,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "networkpolicy",
				DefaultContinue: true,
				Init:            kubernetes.Init,
				Checks: []checkActionner{
					kubernetes.CheckPodExist,
				},
				CheckParameters: networkpolicy.CheckParameters,
				Action:          networkpolicy.NetworkPolicy,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "exec",
				DefaultContinue: true,
				Init:            kubernetes.Init,
				Checks: []checkActionner{
					kubernetes.CheckPodExist,
				},
				CheckParameters: exec.CheckParameters,
				Action:          exec.Exec,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "script",
				DefaultContinue: true,
				Init:            kubernetes.Init,
				Checks: []checkActionner{
					kubernetes.CheckPodExist,
				},
				CheckParameters: script.CheckParameters,
				Action:          script.Script,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "log",
				DefaultContinue: true,
				Init:            kubernetes.Init,
				Checks: []checkActionner{
					kubernetes.CheckPodExist,
				},
				CheckParameters: logActionner.CheckParameters,
				Action:          logActionner.Log,
			},
		)
	}

	return defaultActionners
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
		for _, actionner := range *defaultActionners {
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
		for _, j := range *defaultActionners {
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

	result, err := actionner.Action(rule, action, event)
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
	if err != nil {
		utils.PrintLog("error", config.LogFormat, log)
		notifiers.Notify(rule, action, event, log)
		return err
	}
	utils.PrintLog("info", config.LogFormat, log)
	notifiers.Notify(rule, action, event, log)
	return nil
}
