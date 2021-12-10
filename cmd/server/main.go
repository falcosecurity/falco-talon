package main

import (
	"fmt"
	"net/http"

	"github.com/Issif/falco-talon/internal/configuration"
	"github.com/Issif/falco-talon/internal/kubernetes"
	"github.com/Issif/falco-talon/internal/rule"
	"github.com/Issif/falco-talon/internal/utils"
)

var config *configuration.Configuration
var rules *[]*rule.Rule
var client kubernetes.Client

func init() {
	config = configuration.CreateConfiguration()
	rules = rule.CreateRules()
	client = kubernetes.CreateClient()
	utils.PrintLog("info", fmt.Sprintf("%v Rules have been successfully loaded", len(*rules)))
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/healthz", healthHandler)

	utils.PrintLog("info", fmt.Sprintf("Falco Talon is up and listening on '%s:%d'", config.ListenAddress, config.ListenPort))

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort), nil); err != nil {
		utils.PrintLog("critical", fmt.Sprintf("%v", err.Error()))
	}
}
