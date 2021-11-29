package configuration

var config *Configuration

// TODO
// manage configuration with file and env vars

type Configuration struct {
	ListenAddress string
	ListenPort    int
}

func CreateConfiguration() *Configuration {
	config = new(Configuration)
	config.ListenAddress = "0.0.0.0"
	config.ListenPort = 2803
	return config
}

func GetConfiguration() *Configuration {
	return config
}
