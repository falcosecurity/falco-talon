package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

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
		rules := ruleengine.ParseRules()
		if rules == nil {
			utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: errors.New("invalid rules"), Message: "rules"})
		}
		actionners.Init()
		notifiers.Init()
		utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: fmt.Sprintf("%v rules have been successfully loaded", len(*rules)), Message: "init"})

		http.HandleFunc("/", handler.MainHandler)
		http.HandleFunc("/healthz", handler.HealthHandler)

		utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: fmt.Sprintf("Falco Talon is up and listening on '%s:%d'", config.ListenAddress, config.ListenPort), Message: "init"})

		srv := http.Server{
			Addr:         fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort),
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
			Handler:      nil,
		}

		go func() {
			ignore := false
			watcher, _ := fsnotify.NewWatcher()
			defer watcher.Close()
			watcher.Add(config.RulesFile)
			for {
				select {
				case event := <-watcher.Events:
					if event.Has(fsnotify.Write) && !ignore {
						ignore = true
						go func() {
							time.Sleep(200 * time.Millisecond)
							ignore = false
						}()
						utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: "changes detected", Message: "rules"})
						r := ruleengine.ParseRules()
						if r == nil {
							utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: errors.New("invalid rules"), Message: "rules"})
							break
						}
						utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: fmt.Sprintf("%v rules have been successfully loaded", len(*rules)), Message: "rules"})
						rules = r
					}
				case err := <-watcher.Errors:
					utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err, Message: "rules"})
				}
			}
		}()

		if err := srv.ListenAndServe(); err != nil {
			utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: err})
		}
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)
	serverCmd.PersistentFlags().StringP("config", "c", filepath.Join(os.Getenv("PWD"), "config.yaml"), "Talon Config File")
}
