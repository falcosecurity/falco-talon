package cmd

import (
	"github.com/falco-talon/falco-talon/actionners"
	"github.com/falco-talon/falco-talon/configuration"
	ruleengine "github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs"
	"github.com/falco-talon/falco-talon/utils"

	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check Falco Talon Rules file",
	Long:  "Check Falco Talon Rules file",
	Run: func(cmd *cobra.Command, _ []string) {
		configFile, _ := cmd.Flags().GetString("config")
		config := configuration.CreateConfiguration(configFile)
		utils.SetLogFormat(config.LogFormat)
		rulesFiles, _ := cmd.Flags().GetStringArray("rules")
		if len(rulesFiles) != 0 {
			config.RulesFiles = rulesFiles
		}
		rules := ruleengine.ParseRules(config.RulesFiles)
		if rules == nil {
			utils.PrintLog("fatal", utils.LogLine{Error: "invalid rules", Message: "rules"})
		}
		defaultActionners := actionners.GetDefaultActionners()
		defaultOutputs := outputs.GetDefaultOutputs()

		valid := true
		if rules != nil {
			for _, i := range *rules {
				for _, j := range i.GetActions() {
					actionner := defaultActionners.FindActionner(j.GetActionner())
					if actionner == nil {
						utils.PrintLog("error", utils.LogLine{Error: "unknown actionner", Rule: i.GetName(), Action: j.GetName(), Actionner: j.GetActionner(), Message: "rules"})
						valid = false
					} else {
						if actionner.CheckParameters != nil {
							if err := actionner.CheckParameters(j); err != nil {
								utils.PrintLog("error", utils.LogLine{Error: err.Error(), Rule: i.GetName(), Action: j.GetName(), Actionner: j.GetActionner(), Message: "rules"})
								valid = false
							}
						}
					}
					o := j.GetOutput()
					if o == nil && actionner.IsOutputRequired() {
						utils.PrintLog("error", utils.LogLine{Error: "an output is required", Rule: i.GetName(), Action: j.GetName(), Actionner: j.GetActionner(), Message: "rules"})
						valid = false
					}
					if actionner != nil {
						o := j.GetOutput()
						if o == nil && actionner.IsOutputRequired() {
							utils.PrintLog("error", utils.LogLine{Error: "an output is required", Rule: i.GetName(), Action: j.GetName(), Actionner: j.GetActionner(), Message: "rules"})
							valid = false
						}
						if o != nil {
							output := defaultOutputs.FindOutput(o.GetTarget())
							if output == nil {
								utils.PrintLog("error", utils.LogLine{Error: "unknown target", Rule: i.GetName(), Action: j.GetName(), OutputTarget: o.GetTarget(), Message: "rules"})
								valid = false
							}
							if len(o.Parameters) == 0 {
								utils.PrintLog("error", utils.LogLine{Error: "missing parameters for the output", Rule: i.GetName(), Action: j.GetName(), OutputTarget: o.GetTarget(), Message: "rules"})
								valid = false
							}
							if output != nil && output.CheckParameters != nil {
								if err := output.CheckParameters(o); err != nil {
									utils.PrintLog("error", utils.LogLine{Error: err.Error(), Rule: i.GetName(), Action: j.GetName(), OutputTarget: o.GetTarget(), Message: "rules"})
									valid = false
								}
							}
						}
					}
				}
			}
		}
		if !valid {
			utils.PrintLog("fatal", utils.LogLine{Error: "invalid rules", Message: "rules"})
		}
		utils.PrintLog("info", utils.LogLine{Result: "rules file valid", Message: "rules"})
	},
}

func init() {
	RootCmd.AddCommand(checkCmd)
}
