package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Falco-Talon/falco-talon/internal/aws/client"
	"github.com/Falco-Talon/falco-talon/internal/events"
	"github.com/Falco-Talon/falco-talon/internal/rules"
	"github.com/Falco-Talon/falco-talon/utils"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/mitchellh/mapstructure"
	"net/http"
)

type LambdaConfig struct {
	AWSLambdaName           string `mapstructure:"aws_lambda_name" validate:"required"`
	AWSLambdaAliasOrVersion string `mapstructure:"aws_lambda_alias_or_version" validate:"omitempty"`
	AWSLambdaInvocationType string `mapstructure:"aws_lambda_invocation_type" validate:"omitempty,oneof=RequestResponse Event DryRun"`
}

func Action(action *rules.Action, event *events.Event) (utils.LogLine, error) {

	lambdaClient := client.GetAWSClient().GetLambdaClient()
	parameters := action.GetParameters()

	lambdaConfig, err := CreateLambdaConfigFromParameters(parameters)
	if err != nil {
		return utils.LogLine{
				Objects: nil,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	objects := map[string]string{
		"name":    lambdaConfig.AWSLambdaName,
		"version": lambdaConfig.AWSLambdaAliasOrVersion,
	}

	payload, err := json.Marshal(event.OutputFields)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	input := &lambda.InvokeInput{
		FunctionName:   &lambdaConfig.AWSLambdaName,
		ClientContext:  nil,
		InvocationType: getInvocationType(lambdaConfig.AWSLambdaInvocationType),
		Payload:        payload,
		Qualifier:      &lambdaConfig.AWSLambdaAliasOrVersion,
	}

	lambdaOutput, err := lambdaClient.Invoke(context.Background(), input)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	status := "success"
	if lambdaOutput.StatusCode != http.StatusOK {
		status = "failure"
	}
	return utils.LogLine{
			Objects: objects,
			Output:  string(lambdaOutput.Payload),
			Status:  status,
		},
		nil
}

func CreateLambdaConfigFromParameters(params map[string]interface{}) (*LambdaConfig, error) {
	var config LambdaConfig

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "mapstructure",
		Result:  &config,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating decoder: %w", err)
	}

	if err := decoder.Decode(params); err != nil {
		return nil, fmt.Errorf("error decoding parameters: %w", err)
	}

	if config.AWSLambdaAliasOrVersion == "" {
		config.AWSLambdaAliasOrVersion = "$LATEST"
	}
	return &config, nil
}

func CheckParameters(action *rules.Action) error {
	parameters := action.GetParameters()

	lambdaConfig, err := CreateLambdaConfigFromParameters(parameters)
	if err != nil {
		return err
	}
	err = utils.ValidateStruct(*lambdaConfig)
	if err != nil {
		return err
	}
	return nil
}

func getInvocationType(invocationType string) types.InvocationType {
	switch invocationType {
	case "RequestResponse":
		return types.InvocationTypeRequestResponse
	case "Event":
		return types.InvocationTypeEvent
	case "DryRun":
		return types.InvocationTypeDryRun
	default:
		return types.InvocationTypeRequestResponse // Default
	}
}
