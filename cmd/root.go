package cmd

import (
	"github.com/spf13/cobra"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/utils"
)

var RootCmd = &cobra.Command{
	Use:   "falco-talon",
	Short: "Falco Talon is a Response Engine for managing threats in Kubernetes",
	Long: `Falco Talon is a Response Engine for managing threats in Kubernetes 
It enhances the solutions proposed by Falco community with a dedicated, 
no-code solution. With easy rules, you can perform actions over compromised pods`,
}

func Execute() {
	config := configuration.GetConfiguration()
	err := RootCmd.Execute()
	if err != nil {
		utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: err.Error()})
	}
}

func init() {
	RootCmd.PersistentFlags().StringP("config", "c", "/etc/falco-talon/config.yaml", "Falco Talon Config File")
	RootCmd.PersistentFlags().StringArrayP("rules", "r", []string{"/etc/falco-talon/rules.yaml"}, "Falco Talon Rules File")
}
