package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Issif/falco-reactionner/internal/configuration"
	"github.com/Issif/falco-reactionner/internal/rule"
)

func init() {
	configuration.CreateConfiguration()
	rule.CreateRules()
	rules := rule.GetRules()
	for _, i := range *rules {
		fmt.Printf("%#v\n", i)
	}
}

func main() {
	config := configuration.GetConfiguration()

	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/healthz", healthHandler)

	log.Printf("[INFO]  : Falco Reactionner is up and listening on %s:%d", config.ListenAddress, config.ListenPort)

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort), nil); err != nil {
		log.Fatalf("[ERROR] : %v", err.Error())
	}
}
