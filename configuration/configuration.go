package configuration

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"

	"github.com/Issif/falco-talon/utils"
)

const (
	defaultListenAddress  string = "0.0.0.0"
	defaultListPort       int    = 2803
	DefaultRulesFile      string = "/etc/falco-talon/rules.yaml"
	defaultWatchRules     bool   = true
	defaultPrintAllEvents bool   = false
)

type Configuration struct {
	Notifiers        map[string]map[string]interface{} `mapstructure:"notifiers"`
	LogFormat        string                            `mapstructure:"log_format"`
	KubeConfig       string                            `mapstructure:"kubeconfig"`
	ListenAddress    string                            `mapstructure:"listen_address"`
	RulesFiles       []string                          `mapstructure:"rules_files"`
	DefaultNotifiers []string                          `mapstructure:"default_notifiers"`
	ListenPort       int                               `mapstructure:"listen_port"`
	WatchRules       bool                              `mapstructure:"watch_rules"`
	PrintAllEvents   bool                              `mapstructure:"print_all_events"`
}

var config *Configuration

func init() {
	config = new(Configuration)
}

func CreateConfiguration(configFile string) *Configuration {
	v := viper.New()
	v.SetDefault("listen_address", defaultListenAddress)
	v.SetDefault("listen_port", defaultListPort)
	v.SetDefault("rules_files", []string{DefaultRulesFile})
	v.SetDefault("kubeconfig", "")
	v.SetDefault("log_format", "color")
	v.SetDefault("default_notifiers", []string{})
	v.SetDefault("watch_rules", defaultWatchRules)
	v.SetDefault("print_all_events", defaultPrintAllEvents)

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if configFile != "" {
		d, f := path.Split(configFile)
		if d == "" {
			d = "."
		}
		v.SetConfigName(f[0 : len(f)-len(filepath.Ext(f))])
		v.AddConfigPath(d)
		err := v.ReadInConfig()
		if err != nil {
			utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: fmt.Sprintf("error when reading config file: '%v'", err.Error())})
		}
	}

	if err := v.Unmarshal(config); err != nil {
		utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: fmt.Sprintf("error unmarshalling config file: '%v'", err.Error())})
	}

	return config
}

func GetConfiguration() *Configuration {
	return config
}

func (c *Configuration) GetDefaultNotifiers() []string {
	return c.DefaultNotifiers
}
