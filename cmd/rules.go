package cmd

import (
	"fmt"

	"github.com/falcosecurity/falco-talon/configuration"
	ruleengine "github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"

	"github.com/jinzhu/copier"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var rulesCmd = &cobra.Command{
	Use:   rulesStr,
	Short: "Manage Falco Talon rules",
	Long:  `Manage the rules loaded by Falco Talon. You can print them in the stdout or check their validity.`,
}

var rulesChecksCmd = &cobra.Command{
	Use:   "check",
	Short: checkRulesStr,
	Long:  checkRulesStr,
	Run: func(cmd *cobra.Command, _ []string) {
		configFile, _ := cmd.Flags().GetString("config")
		config := configuration.CreateConfiguration(configFile)
		utils.SetLogFormat(config.LogFormat)
		rulesFiles, _ := cmd.Flags().GetStringArray(rulesStr)
		if len(rulesFiles) != 0 {
			config.RulesFiles = rulesFiles
		}
		rules := ruleengine.ParseRules(config.RulesFiles)
		if rules == nil {
			utils.PrintLog(utils.FatalStr, utils.LogLine{Error: invalidRulesStr, Message: rulesStr})
		}
		if !validateRules(rules) {
			utils.PrintLog(utils.FatalStr, utils.LogLine{Error: invalidRulesStr, Message: rulesStr})
		}
		utils.PrintLog(utils.InfoStr, utils.LogLine{Result: "rules file valid", Message: rulesStr})
	},
}

var rulesPrintCmd = &cobra.Command{
	Use:   "print",
	Short: "Print the loaded by Falco Talon in the stdout",
	Long:  "Print the loaded by Falco Talon in the stdout.",
	Run: func(cmd *cobra.Command, _ []string) {
		configFile, _ := cmd.Flags().GetString("config")
		config := configuration.CreateConfiguration(configFile)
		utils.SetLogFormat(config.LogFormat)
		rulesFiles, _ := cmd.Flags().GetStringArray(rulesStr)
		if len(rulesFiles) != 0 {
			config.RulesFiles = rulesFiles
		}
		rules := ruleengine.ParseRules(config.RulesFiles)
		if rules == nil {
			utils.PrintLog(utils.FatalStr, utils.LogLine{Error: invalidRulesStr, Message: rulesStr})
		}
		type yamlFile struct {
			Name        string   `yaml:"rule"`
			Description string   `yaml:"description,omitempty"`
			Continue    string   `yaml:"continue,omitempty"`
			DryRun      string   `yaml:"dry_run,omitempty"`
			Notifiers   []string `yaml:"notifiers,omitempty"`
			Actions     []struct {
				Parameters map[string]any `yaml:"parameters,omitempty"`
				Output     struct {
					Parameters map[string]any `yaml:"parameters"`
					Target     string         `yaml:"target"`
				} `yaml:"output,omitempty"`
				Name               string   `yaml:"action"`
				Description        string   `yaml:"description,omitempty"`
				Actionner          string   `yaml:"actionner"`
				Continue           string   `yaml:"continue,omitempty"`
				IgnoreErrors       string   `yaml:"ignore_errors,omitempty"`
				AdditionalContexts []string `yaml:"additional_contexts,omitempty"`
			} `yaml:"actions"`
			Match struct {
				OutputFields []string `yaml:"output_fields,omitempty"`
				Priority     string   `yaml:"priority,omitempty"`
				Source       string   `yaml:"source,omitempty"`
				Rules        []string `yaml:"rules,omitempty"`
				Tags         []string `yaml:"tags,omitempty"`
			} `yaml:"match"`
		}

		var q []yamlFile
		if err := copier.Copy(&q, &rules); err != nil {
			utils.PrintLog(utils.FatalStr, utils.LogLine{Error: err.Error()})
		}

		b, _ := yaml.Marshal(q)
		fmt.Printf("---\n%s", b)
	},
}
