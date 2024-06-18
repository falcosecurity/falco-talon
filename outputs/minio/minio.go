package minio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	miniosdk "github.com/minio/minio-go/v7"

	"github.com/falco-talon/falco-talon/internal/events"
	minio "github.com/falco-talon/falco-talon/internal/minio/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	Bucket string `mapstructure:"bucket" validate:"required"`
	Prefix string `mapstructure:"prefix" validate:""`
}

const (
	defaultContentType string = "text/plain; charset=utf-8"
)

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

	config.Prefix = strings.TrimSuffix(config.Prefix, "/") + "/"

	var key string
	if data.Namespace != "" && data.Pod != "" {
		key = fmt.Sprintf("%v_%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Namespace, data.Pod, strings.ReplaceAll(data.Name, "/", "_"))
	} else {
		key = fmt.Sprintf("%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Hostname, strings.ReplaceAll(data.Name, "/", "_"))
	}

	objects := map[string]string{
		"file":   data.Name,
		"bucket": config.Bucket,
		"prefix": config.Prefix,
		"key":    key,
	}

	if err := putObject(config.Bucket, config.Prefix, key, *data); err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the file '%v' has been uploaded as the key '%v' to the bucket '%v'", data.Name, config.Prefix+key, config.Bucket),
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

func CheckBucketExist(output *rules.Output, _ *events.Event) error {
	parameters := output.GetParameters()
	var config Config
	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return err
	}

	ctx := context.Background()
	exist, err := minio.GetClient().BucketExists(ctx, config.Bucket)
	if err != nil {
		return err
	}
	if exist {
		return nil
	}

	return fmt.Errorf("the bucket '%v' does not exist", config.Bucket)
}

func putObject(bucket, prefix, key string, data model.Data) error {
	client := minio.GetClient()
	if client == nil {
		return errors.New("client error")
	}

	ctx := context.Background()
	body := bytes.NewReader(data.Bytes)

	_, err := client.PutObject(ctx, bucket, prefix+key, body, int64(len(data.Bytes)), miniosdk.PutObjectOptions{ContentType: defaultContentType})
	if err != nil {
		return err
	}
	return nil
}
