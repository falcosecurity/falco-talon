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
)

func Action(action *rules.Action, event *events.Event) (utils.LogLine, error) {

	lambdaClient := client.GetAWSClient().LambdaClient()
	parameters := action.GetParameters()

	lambdaConfig, err := NewLambdaConfig(parameters)
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

	_, err = lambdaClient.Invoke(context.Background(), input)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}

	output := fmt.Sprintf("the lambda %v:%v has been executed.", lambdaConfig.AWSLambdaName, lambdaConfig.AWSLambdaAliasOrVersion)

	return utils.LogLine{
			Objects: objects,
			Output:  output,
			Status:  "success",
		},
		nil
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

func NewLambdaConfig(params map[string]interface{}) (*LambdaConfig, error) {
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

	return &config, nil
}

type LambdaConfig struct {
	AWSLambdaName           string `mapstructure:"aws_lambda_name"`
	AWSLambdaAliasOrVersion string `mapstructure:"aws_lambda_alias_or_version"`
	AWSLambdaInvocationType string `mapstructure:"aws_lambda_invocation_type"`
}

func CheckParameters(action *rules.Action) error {
	parameters := action.GetParameters()
	if err := utils.CheckParameters(parameters, "aws_lambda_name", utils.StringStr, nil, true); err != nil {
		return err
	}
	if err := utils.CheckParameters(parameters, "aws_lambda_alias_or_version", utils.StringStr, nil, false); err != nil {
		return err
	}
	if err := utils.CheckParameters(parameters, "aws_lambda_invocation_type", utils.StringStr, nil, false, "RequestResponse", "DryRun", "Event"); err != nil {
		return err
	}
	return nil
}
