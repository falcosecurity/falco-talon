package configuration

import (
	"fmt"
	"path"
	"strings"

	"github.com/spf13/viper"

	"github.com/falco-talon/falco-talon/utils"
)

const (
	defaultListenAddress           string = "0.0.0.0"
	defaultListPort                int    = 2803
	defaultRulesFile               string = "/etc/falco-talon/rules.yaml"
	defaultWatchRules              bool   = true
	defaultPrintAllEvents          bool   = false
	defaultDeduplicationEnabled    bool   = true
	defaultDeduplicationTimeWindow int    = 5
)

type Configuration struct {
	Notifiers        map[string]map[string]interface{} `mapstructure:"notifiers"`
	AwsConfig        AwsConfig                         `mapstructure:"aws"`
	LogFormat        string                            `mapstructure:"log_format"`
	KubeConfig       string                            `mapstructure:"kubeconfig"`
	ListenAddress    string                            `mapstructure:"listen_address"`
	RulesFiles       []string                          `mapstructure:"rules_files"`
	DefaultNotifiers []string                          `mapstructure:"default_notifiers"`
	ListenPort       int                               `mapstructure:"listen_port"`
	Deduplication    deduplication                     `mapstructure:"deduplication"`
	WatchRules       bool                              `mapstructure:"watch_rules"`
	PrintAllEvents   bool                              `mapstructure:"print_all_events"`
}

type deduplication struct {
	Enabled           bool `mapstructure:"enabled"`
	TimeWindowSeconds int  `mapstructure:"time_window_seconds"`
}

var config *Configuration

func init() {
	config = new(Configuration)
}

func CreateConfiguration(configFile string) *Configuration {
	v := viper.New()
	v.SetDefault("listen_address", defaultListenAddress)
	v.SetDefault("listen_port", defaultListPort)
	v.SetDefault("rules_files", []string{defaultRulesFile})
	v.SetDefault("kubeconfig", "")
	v.SetDefault("log_format", "color")
	v.SetDefault("default_notifiers", []string{})
	v.SetDefault("watch_rules", defaultWatchRules)
	v.SetDefault("print_all_events", defaultPrintAllEvents)
	v.SetDefault("deduplication.enabled", defaultDeduplicationEnabled)
	v.SetDefault("deduplication.time_window_seconds", defaultDeduplicationTimeWindow)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if configFile != "" {
		d, f := path.Split(configFile)
		if d == "" {
			d = "."
		}
		v.AddConfigPath(d)
		v.SetConfigFile(f)
		err := v.ReadInConfig()
		if err != nil {
			utils.PrintLog("fatal", utils.LogLine{Error: fmt.Sprintf("error when reading config file: '%v'", err.Error()), Message: "config"})
		}
	}

	if err := v.Unmarshal(config); err != nil {
		utils.PrintLog("fatal", utils.LogLine{Error: fmt.Sprintf("error unmarshalling config file: '%v'", err.Error()), Message: "config"})
	}

	return config
}

func GetConfiguration() *Configuration {
	return config
}

func (c *Configuration) GetDefaultNotifiers() []string {
	return c.DefaultNotifiers
}

type AwsConfig struct {
	Region     string `mapstructure:"region"`
	AccessKey  string `mapstructure:"access_key"`
	SecretKey  string `mapstructure:"secret_key"`
	RoleArn    string `mapstructure:"role_arn"`
	ExternalID string `mapstructure:"external_id"`
}
