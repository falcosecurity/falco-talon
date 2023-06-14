package cmd

import (
	"github.com/Issif/falco-talon/actionners"
	"github.com/Issif/falco-talon/configuration"
	ruleengine "github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"

	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check Falco Talon Rules file",
	Long:  "Check Falco Talon Rules file",
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		config := configuration.CreateConfiguration(configFile)
		rulesFile, _ := cmd.Flags().GetString("rules")
		if rulesFile != "" {
			config.RulesFile = rulesFile
		}
		rules := ruleengine.ParseRules(config.RulesFile)
		if rules == nil {
			utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: "invalid rules", Message: "rules"})
		}
		actionners.Init()
		actions := actionners.GetActionners()
		for _, i := range *actions {
			for _, j := range *rules {
				if i.CheckParameters != nil {
					if err := i.CheckParameters(j); err != nil {
						utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err.Error(), Rule: j.GetName(), Message: "rules"})
					}
				}
			}
		}
		utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: "rules file valid", Message: "rules"})
	},
}

func init() {
	RootCmd.AddCommand(checkCmd)
}
