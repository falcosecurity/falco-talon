package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Issif/falco-reactionner/internal/configuration"
	"github.com/Issif/falco-reactionner/internal/rule"
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

	log.Printf("[INFO]  : Falco Reactionner is up and listening on %s:%d", config.ListenAddress, config.ListenPort)

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort), nil); err != nil {
		log.Fatalf("[ERROR] : %v", err.Error())
	}
}
