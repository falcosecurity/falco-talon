package main

import (
	"fmt"
	"net/http"

	"github.com/Issif/falco-reactionner/internal/configuration"
	"github.com/Issif/falco-reactionner/internal/rule"
	"github.com/Issif/falco-reactionner/internal/utils"
)

var config *configuration.Configuration
var rules *rule.Rules

func init() {
	config = configuration.CreateConfiguration()
	rules = rule.CreateRules()
	for _, i := range *rules {
		fmt.Printf("%#v\n", i)
	}
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/healthz", healthHandler)

	utils.PrintLog("info", fmt.Sprintf("Falco Talon is up and listening on %s:%d", config.ListenAddress, config.ListenPort))

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort), nil); err != nil {
		utils.PrintLog("critical", fmt.Sprintf("%v", err.Error()))
	}
}
