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
)

func Action(r *rules.Action, event *events.Event) (utils.LogLine, error) {

	lambdaClient := client.GetAWSClient().LambdaClient()
	parameters := r.GetParameters()

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
		InvocationType: "",
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

// NewLambdaConfig creates a new LambdaConfig with default values.
// Each action would have your own data handler, so we can perform validation and keep defaults in a single place for each action
func NewLambdaConfig(params map[string]interface{}) (LambdaConfig, error) {
	var lambdaConfig LambdaConfig

	// Check and set aws_lambda_name
	if name, ok := params["aws_lambda_name"].(string); ok && name != "" {
		lambdaConfig.AWSLambdaName = name
	} else {
		return LambdaConfig{}, fmt.Errorf("aws_lambda_name is required and must be a string")
	}

	lambdaConfig.AWSLambdaAliasOrVersion = "$LATEST" // Default value
	if version, ok := params["aws_lambda_alias_or_version"].(string); ok && version != "" {
		lambdaConfig.AWSLambdaAliasOrVersion = version
	}

	return lambdaConfig, nil
}

type LambdaConfig struct {
	AWSLambdaName           string
	AWSLambdaAliasOrVersion string
}
