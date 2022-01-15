package cmd

import (
	"github.com/Issif/falco-talon/utils"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "falco-talon",
	Short: "Falco Talon is a Response Engine for managing threats in Kubernetes.",
	Long: `Falco Talon is a Response Engine for managing threats in Kubernetes. 
It enhances the solutions proposed by Falco community with a dedicated, 
no-code solution. With easy rules, you can perform actions over compromised pods.`,
}

func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		utils.PrintLog("critical", err.Error())
	}
}
