package configuration

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/Issif/falco-talon/internal/utils"
)

var config *Configuration

// TODO
// manage configuration with file and env vars

type Configuration struct {
	Notifiers     Notifiers
	RulesFile     string
	KubeConfig    string
	ListenAddress string
	ListenPort    int
}

type Notifiers struct {
	Slack SlackConfig
}

type SlackConfig struct {
	WebhookURL string
	Footer     string
	Icon       string
	Username   string
}

func CreateConfiguration() *Configuration {
	config = new(Configuration)
	configFile := kingpin.Flag("config", "Config file").Short('c').Default("./falco-talon.yaml").ExistingFile()
	// config.ListenAddress = kingpin.Flag("address", "Listen Address").Short('a').Default("0.0.0.0").String()
	// config.ListenPort = kingpin.Flag("port", "Listen Port").Short('p').Default("2803").Int()
	// config.RulesFile = kingpin.Flag("rules", "Rules file").Short('r').Default("./rules.yaml").ExistingFile()
	// config.KubeConfig = kingpin.Flag("kubeconfig", "Kube Config").Short('k').ExistingFile()
	version := kingpin.Flag("version", "falco-talon version").Short('v').Bool()
	kingpin.Parse()

	if *version {
		v := GetVersionInfo()
		fmt.Println(v.String())
		os.Exit(0)
	}

	v := viper.New()
	v.SetDefault("ListenAddress", "0.0.0.0")
	v.SetDefault("ListenPort", 2803)
	v.SetDefault("RulesFile", "./rules.yaml")
	v.SetDefault("KubeConfig", filepath.Join(os.Getenv("HOME"), ".kube", "config"))

	v.SetDefault("Slack.Icon", "https://upload.wikimedia.org/wikipedia/commons/2/26/Circaetus_gallicus_claw.jpg")
	v.SetDefault("Slack.Username", "Falco Talon")
	v.SetDefault("Slack.Footer", "")

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if *configFile != "" {
		d, f := path.Split(*configFile)
		if d == "" {
			d = "."
		}
		v.SetConfigName(f[0 : len(f)-len(filepath.Ext(f))])
		v.AddConfigPath(d)
		err := v.ReadInConfig()
		if err != nil {
			utils.PrintLog("critical", fmt.Sprintf("Error when reading config file: %v", err.Error()))
		}
	}

	if err := v.Unmarshal(config); err != nil {
		utils.PrintLog("critical", fmt.Sprintf("Error unmarshalling config: %v", err.Error()))
	}

	fmt.Printf("%#v\n", config)

	return config
}

func GetConfiguration() *Configuration {
	return config
}
