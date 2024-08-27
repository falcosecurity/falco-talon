package models

type Information struct {
	FullName             string   `yaml:"fullname"`
	Name                 string   `yaml:"name"`
	Category             string   `yaml:"category"`
	Description          string   `yaml:"description"`
	Source               string   `yaml:"source"`
	Permissions          string   `yaml:"permissions"`
	Example              string   `yaml:"example"`
	RequiredOutputFields []string `yaml:"required_output_fields"`
	Continue             bool     `yaml:"continue"`
	UseContext           bool     `yaml:"use_context"`
	AllowOutput          bool     `yaml:"allow_output"`
	RequireOutput        bool     `yaml:"require_output"`
}

type Data struct {
	Name    string
	Objects map[string]string
	Bytes   []byte
}

type Parameters interface{}
