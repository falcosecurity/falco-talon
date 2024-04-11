package checks

import (
	"context"

	lambdaActionner "github.com/falco-talon/falco-talon/actionners/aws/lambda"
	"github.com/falco-talon/falco-talon/internal/aws/client"
	"github.com/falco-talon/falco-talon/internal/events"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func CheckLambdaExist(_ *events.Event, action *rules.Action) error {
	lambdaClient := client.GetAWSClient().GetLambdaClient()
	parameters := action.GetParameters()

	var lambdaConfig lambdaActionner.Config
	err := utils.DecodeParams(parameters, &lambdaConfig)
	if err != nil {
		return err
	}
	_, err = lambdaClient.GetFunction(context.Background(), &lambda.GetFunctionInput{
		FunctionName: &lambdaConfig.AWSLambdaName,
	})
	if err != nil {
		return err
	}
	return nil
}
