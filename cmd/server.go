package cmd

import (
	"errors"
	"fmt"
	"net/http"
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
	Short: "Start Falco Talon",
	Long:  "Start Falco Talon",
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		config := configuration.CreateConfiguration(configFile)
		rulesFile, _ := cmd.Flags().GetString("rules")
		if rulesFile != "" && rulesFile != configuration.DefaultRulesFile {
			config.RulesFile = rulesFile
		}
		fmt.Println(config.RulesFile)
		rules := ruleengine.ParseRules(config.RulesFile)
		if rules == nil {
			utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: errors.New("invalid rules"), Message: "rules"})
		}
		actionners.Init()
		notifiers.Init()
		if rules != nil {
			utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: fmt.Sprintf("%v rules have been successfully loaded", len(*rules)), Message: "init"})
		}

		http.HandleFunc("/", handler.MainHandler)
		http.HandleFunc("/healthz", handler.HealthHandler)

		if config.WatchRules {
			utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: "watch of rules enabled", Message: "init"})
		}

		utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: fmt.Sprintf("Falco Talon is up and listening on '%s:%d'", config.ListenAddress, config.ListenPort), Message: "init"})

		srv := http.Server{
			Addr:         fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort),
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
			Handler:      nil,
		}

		if config.WatchRules {
			go func() {
				ignore := false
				watcher, err := fsnotify.NewWatcher()
				if err != nil {
					utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err, Message: "rules"})
					return
				}
				defer watcher.Close()
				if err := watcher.Add(config.RulesFile); err != nil {
					utils.PrintLog("error", config.LogFormat, utils.LogLine{Error: err, Message: "rules"})
					return
				}
				for {
					select {
					case event := <-watcher.Events:
						if event.Has(fsnotify.Write) && !ignore {
							ignore = true
							go func() {
								time.Sleep(500 * time.Millisecond)
								ignore = false
							}()
							utils.PrintLog("info", config.LogFormat, utils.LogLine{Result: "changes detected", Message: "rules"})
							r := ruleengine.ParseRules(config.RulesFile)
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
		}

		if err := srv.ListenAndServe(); err != nil {
			utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: err})
		}
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)
}
