package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/falco-talon/falco-talon/internal/events"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	Destination string `mapstructure:"destination" validate:"required"`
}

func Output(output *rules.Output, data *model.Data) (utils.LogLine, error) {
	parameters := output.GetParameters()
	var config Config
	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  "failure",
		}, err
	}

	var key string
	if data.Namespace != "" && data.Pod != "" {
		key = fmt.Sprintf("%v_%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Namespace, data.Pod, strings.ReplaceAll(data.Name, "/", "_"))
	} else {
		key = fmt.Sprintf("%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Hostname, strings.ReplaceAll(data.Name, "/", "_"))
	}

	dstfile := fmt.Sprintf("%v/%v", strings.TrimSuffix(config.Destination, "/"), key)

	objects := map[string]string{
		"file":        data.Name,
		"destination": dstfile,
	}

	if err := os.WriteFile(dstfile, data.Bytes, 0600); err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the file '%v' has been copied to '%v'", filepath.Base(data.Name), dstfile),
		Status:  "success",
	}, nil
}

func CheckParameters(output *rules.Output) error {
	parameters := output.GetParameters()

	var config Config

	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(config)
	if err != nil {
		return err
	}

	return nil
}

func CheckFolderExist(output *rules.Output, event *events.Event) error {
	parameters := output.GetParameters()
	var config Config
	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return err
	}

	event.ExportEnvVars()

	dstFolder := os.ExpandEnv(config.Destination)
	if _, err := os.Open(dstFolder); os.IsNotExist(err) {
		return fmt.Errorf("folder '%v' does not exist", dstFolder)
	}

	return nil
}
