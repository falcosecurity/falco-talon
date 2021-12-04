package configuration

import "gopkg.in/alecthomas/kingpin.v2"

var config *Configuration

// TODO
// manage configuration with file and env vars

type Configuration struct {
	ListenAddress *string
	ListenPort    *int
	RulesFile     *string
}

func CreateConfiguration() *Configuration {
	config = new(Configuration)
	config.ListenAddress = kingpin.Flag("address", "Listen Address").Short('a').Default("0.0.0.0").String()
	config.ListenPort = kingpin.Flag("port", "Listen Port").Short('p').Default("2803").Int()
	config.RulesFile = kingpin.Flag("rules", "Rules file").Short('r').Default("./rules.yaml").ExistingFile()
	kingpin.Parse()
	return config
}

func GetConfiguration() *Configuration {
	return config
}
