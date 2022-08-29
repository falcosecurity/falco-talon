package cmd

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Issif/falco-talon/actionners"
	"github.com/Issif/falco-talon/configuration"
	"github.com/Issif/falco-talon/internal/handler"
	ruleengine "github.com/Issif/falco-talon/internal/rules"
	"github.com/Issif/falco-talon/notifiers"
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
		actionners.Init()
		notifiers.Init()
		utils.PrintLog("info", fmt.Sprintf("%v Rules have been successfully loaded", len(*rules)))

		http.HandleFunc("/", handler.MainHandler)
		http.HandleFunc("/healthz", handler.HealthHandler)

		utils.PrintLog("info", fmt.Sprintf("Falco Talon is up and listening on '%s:%d'", config.ListenAddress, config.ListenPort))

		srv := http.Server{
			Addr:         fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort),
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
			Handler:      nil,
		}

		if err := srv.ListenAndServe(); err != nil {
			utils.PrintLog("critical", fmt.Sprintf("%v", err.Error()))
		}
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)
	serverCmd.PersistentFlags().StringP("config", "c", filepath.Join(os.Getenv("PWD"), "config.yaml"), "Talon Config File")
}
