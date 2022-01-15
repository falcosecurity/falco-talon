package cmd

import (
	"fmt"

	"github.com/Issif/falco-talon/configuration"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version of Falco Talon.",
	Long:  "Print version of Falco Talon",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(configuration.GetVersionInfo().String())
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
