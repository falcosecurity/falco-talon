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
	defaultListenAddress = "0.0.0.0"
	defaultListPort      = 2803
	defaultRulesFile     = "./rules.yaml"
)

// type Actionner interface {
// 	Run(event *events.Event, rule *rules.Rule)
// }

// type Notifier interface {
// 	Notifiy(event *events.Event, rule *rules.Rule)
// }

// TODO
// manage configuration with file and env vars

type Configuration struct {
	Notifiers        map[string]map[string]interface{}
	LogFormat        string
	KubeConfig       string
	ListenAddress    string
	RulesFile        string
	DefaultNotifiers []string
	ListenPort       int
}

var config *Configuration

func init() {
	config = new(Configuration)
}

func CreateConfiguration(configFile string) *Configuration {
	v := viper.New()
	v.SetDefault("ListenAddress", defaultListenAddress)
	v.SetDefault("ListenPort", defaultListPort)
	v.SetDefault("RulesFile", defaultRulesFile)
	v.SetDefault("KubeConfig", "")
	v.SetDefault("Logformat", "color")
	v.SetDefault("DefaultNotifiers", []string{})

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
			utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: fmt.Errorf("error when reading config file: %v", err.Error())})
		}
	}

	if err := v.Unmarshal(config); err != nil {
		utils.PrintLog("fatal", config.LogFormat, utils.LogLine{Error: fmt.Errorf("error unmarshalling config: %v", err.Error())})
	}

	// fmt.Printf("%#v\n", config)

	return config
}

func GetConfiguration() *Configuration {
	return config
}

func (c *Configuration) GetDefaultNotifiers() []string {
	return c.DefaultNotifiers
}
