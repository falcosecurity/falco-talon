package cmd

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/handler"
	"github.com/Issif/falco-talon/internal/kubernetes"
	ruleengine "github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/utils"

	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start Falco Talon.",
	Long:  "Start Falco Talon",
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		config := configuration.CreateConfiguration(configFile)
		rules := ruleengine.CreateRules()
		kubernetes.CreateClient()
		// slack.Init()
		utils.PrintLog("info", fmt.Sprintf("%v Rules have been successfully loaded", len(*rules)))

		http.HandleFunc("/", handler.MainHandler)
		http.HandleFunc("/ping", handler.PingHandler)
		http.HandleFunc("/healthz", handler.HealthHandler)

		utils.PrintLog("info", fmt.Sprintf("Falco Talon is up and listening on '%s:%d'", config.ListenAddress, config.ListenPort))

		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort), nil); err != nil {
			utils.PrintLog("critical", fmt.Sprintf("%v", err.Error()))
		}
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)
	serverCmd.PersistentFlags().StringP("config", "c", filepath.Join(os.Getenv("PWD"), "config.yaml"), "Talon Config File")
}
