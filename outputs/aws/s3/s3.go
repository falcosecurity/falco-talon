package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	aws "github.com/falco-talon/falco-talon/internal/aws/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	Bucket string `mapstructure:"bucket" validate:"required"`
	Prefix string `mapstructure:"prefix" validate:""`
	Region string `mapstructure:"region" validate:""`
}

func Output(output *rules.Output, data *model.Data) (utils.LogLine, error) {
	parameters := output.GetParameters()
	var config Config
	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, err
	}

	config.Prefix = strings.TrimSuffix(config.Prefix, "/")
	config.Prefix = strings.TrimPrefix(config.Prefix, "/") + "/"

	var key string
	if data.Namespace != "" && data.Pod != "" {
		key = fmt.Sprintf("%v_%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Namespace, data.Pod, strings.ReplaceAll(data.Name, "/", "_"))
	} else {
		key = fmt.Sprintf("%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Hostname, strings.ReplaceAll(data.Name, "/", "_"))
	}

	var region string
	awsClient := aws.GetAWSClient()
	if awsClient != nil {
		region = awsClient.GetRegion()
	}
	if config.Region != "" {
		region = config.Region
	}

	objects := map[string]string{
		"file":   data.Name,
		"bucket": config.Bucket,
		"prefix": config.Prefix,
		"key":    key,
		"region": region,
	}

	if err := putObject(region, config.Bucket, config.Prefix, key, *data); err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the file '%v' has been uploaded as the key '%v' to the bucket '%v'", data.Name, config.Prefix+key, config.Bucket),
		Status:  utils.SuccessStr,
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

func putObject(region, bucket, prefix, key string, data model.Data) error {
	client := aws.GetS3Client()
	if client == nil {
		return errors.New("client error")
	}

	ctx := context.Background()
	body := bytes.NewReader(data.Bytes)

	opts := func(o *s3.Options) {
		o.Region = region
	}

	_, err := client.PutObject(
		ctx,
		&s3.PutObjectInput{
			Bucket: awssdk.String(bucket),
			Key:    awssdk.String(prefix + key),
			Body:   body,
		},
		opts,
	)
	if err != nil {
		return err
	}
	return nil
}
