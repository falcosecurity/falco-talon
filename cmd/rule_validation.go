package cmd

import (
	"github.com/falcosecurity/falco-talon/actionners"
	ruleengine "github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/outputs"
	"github.com/falcosecurity/falco-talon/utils"
)

func validateRules(rules *[]*ruleengine.Rule) bool {
	defaultActionners := actionners.ListDefaultActionners()
	defaultOutputs := outputs.ListDefaultOutputs()

	valid := true
	for _, rule := range *rules {
		for _, action := range rule.GetActions() {
			actionner := defaultActionners.FindActionner(action.GetActionner())
			if actionner == nil {
				utils.PrintLog(utils.ErrorStr, utils.LogLine{
					Error:     "unknown actionner",
					Rule:      rule.GetName(),
					Action:    action.GetName(),
					Actionner: action.GetActionner(),
					Message:   rulesStr,
				})
				valid = false
				continue
			}

			if err := actionner.CheckParameters(action); err != nil {
				utils.PrintLog(utils.ErrorStr, utils.LogLine{
					Error:     err.Error(),
					Rule:      rule.GetName(),
					Action:    action.GetName(),
					Actionner: action.GetActionner(),
					Message:   rulesStr,
				})
				valid = false
			}

			output := action.GetOutput()
			if output == nil {
				if actionner.Information().RequireOutput {
					utils.PrintLog(utils.ErrorStr, utils.LogLine{
						Error:     "an output is required",
						Rule:      rule.GetName(),
						Action:    action.GetName(),
						Actionner: action.GetActionner(),
						Message:   rulesStr,
					})
					valid = false
				}
				continue
			}

			target := defaultOutputs.FindOutput(output.GetTarget())
			if target == nil {
				utils.PrintLog(utils.ErrorStr, utils.LogLine{
					Error:        "unknown target",
					Rule:         rule.GetName(),
					Action:       action.GetName(),
					OutputTarget: output.GetTarget(),
					Message:      rulesStr,
				})
				valid = false
				continue
			}

			if len(output.Parameters) == 0 {
				utils.PrintLog(utils.ErrorStr, utils.LogLine{
					Error:        "missing parameters for the output",
					Rule:         rule.GetName(),
					Action:       action.GetName(),
					OutputTarget: output.GetTarget(),
					Message:      rulesStr,
				})
				valid = false
				continue
			}

			if err := target.CheckParameters(output); err != nil {
				utils.PrintLog(utils.ErrorStr, utils.LogLine{
					Error:        err.Error(),
					Rule:         rule.GetName(),
					Action:       action.GetName(),
					OutputTarget: output.GetTarget(),
					Message:      rulesStr,
				})
				valid = false
			}
		}
	}

	return valid
}
