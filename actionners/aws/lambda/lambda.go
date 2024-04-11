package lambda

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/falco-talon/falco-talon/internal/aws/client"
	"github.com/falco-talon/falco-talon/internal/events"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	AWSLambdaName           string `mapstructure:"aws_lambda_name" validate:"required"`
	AWSLambdaAliasOrVersion string `mapstructure:"aws_lambda_alias_or_version" validate:"omitempty"`
	AWSLambdaInvocationType string `mapstructure:"aws_lambda_invocation_type" validate:"omitempty,oneof=RequestResponse Event DryRun"`
}

func Action(action *rules.Action, event *events.Event) (utils.LogLine, error) {
	lambdaClient := client.GetAWSClient().GetLambdaClient()
	parameters := action.GetParameters()

	var lambdaConfig Config
	err := utils.DecodeParams(parameters, &lambdaConfig)
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

	payload, err := json.Marshal(event)
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
		Qualifier:      getLambdaVersion(&lambdaConfig.AWSLambdaAliasOrVersion),
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
	if lambdaOutput.StatusCode != http.StatusOK && lambdaOutput.StatusCode != http.StatusNoContent {
		status = "failure"
	}
	return utils.LogLine{
			Objects: objects,
			Output:  string(lambdaOutput.Payload),
			Status:  status,
		},
		nil
}

func CheckParameters(action *rules.Action) error {
	parameters := action.GetParameters()

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

func getLambdaVersion(qualifier *string) *string {
	if qualifier == nil || *qualifier == "" {
		defaultVal := "$LATEST"
		return &defaultVal
	}
	return qualifier
}
