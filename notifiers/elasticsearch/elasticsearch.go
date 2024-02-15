package elasticsearch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Falco-Talon/falco-talon/notifiers/http"
	"github.com/Falco-Talon/falco-talon/utils"
)

type Settings struct {
	CustomHeaders       map[string]string `field:"custom_headers"`
	URL                 string            `field:"url"`
	User                string            `field:"user"`
	Password            string            `field:"password"`
	Suffix              string            `field:"suffix" default:"daily"`
	Index               string            `field:"index" default:"falco-talon"`
	NumberOfShards      int               `field:"number_of_shards" default:"3"`
	NumberOfReplicas    int               `field:"number_of_replicas" default:"3"`
	CreateIndexTemplate bool              `field:"create_index_template" default:"true"`
}

const docType string = "/_doc"
const indexTemplate string = "/_index_template/falco-talon"

var settings *Settings

func Init(fields map[string]interface{}) error {
	settings = new(Settings)
	settings = utils.SetFields(settings, fields).(*Settings)
	if err := checkSettings(settings); err != nil {
		return err
	}
	if settings.CreateIndexTemplate {
		client := http.NewClient("GET", "", "", settings.CustomHeaders)
		if settings.User != "" && settings.Password != "" {
			client.SetBasicAuth(settings.User, settings.Password)
		}
		if err := client.Request(settings.URL+indexTemplate, nil); err != nil {
			if err.Error() == "resource not found" {
				client.SetHTTPMethod("PUT")
				m := strings.ReplaceAll(mapping, "${SHARDS}", fmt.Sprintf("%v", settings.NumberOfShards))
				m = strings.ReplaceAll(m, "${REPLICAS}", fmt.Sprintf("%v", settings.NumberOfReplicas))
				j := make(map[string]interface{})
				if err := json.Unmarshal([]byte(m), &j); err != nil {
					return err
				}
				if err := client.Request(settings.URL+indexTemplate, j); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func Notify(log utils.LogLine) error {
	client := http.DefaultClient()

	current := time.Now()
	var u string
	switch settings.Suffix {
	case "none":
		u = settings.URL + "/" + settings.Index + docType
	case "monthly":
		u = settings.URL + "/" + settings.Index + "-" + current.Format("2006.01") + docType
	case "annually":
		u = settings.URL + "/" + settings.Index + "-" + current.Format("2006") + docType
	default:
		u = settings.URL + "/" + settings.Index + "-" + current.Format("2006.01.02") + docType
	}

	log.Time = time.Now().Format(time.RFC3339)

	if err := client.Request(u, log); err != nil {
		return err
	}

	return nil
}

func checkSettings(settings *Settings) error {
	if settings.URL == "" {
		return errors.New("wrong `url` setting")
	}
	if settings.NumberOfShards < 1 {
		return errors.New("wrong `number_of_shards` setting")
	}
	if settings.NumberOfReplicas < 1 {
		return errors.New("wrong `number_of_replcicas` setting")
	}

	if err := http.CheckURL(settings.URL); err != nil {
		return err
	}

	return nil
}
