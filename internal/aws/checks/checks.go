package checks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/lambda"

	lambdaActionner "github.com/falco-talon/falco-talon/actionners/aws/lambda"
	aws "github.com/falco-talon/falco-talon/internal/aws/client"
	"github.com/falco-talon/falco-talon/internal/events"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

func CheckLambdaExist(_ *events.Event, action *rules.Action) error {
	client := aws.GetLambdaClient()
	parameters := action.GetParameters()

	var lambdaConfig lambdaActionner.Config
	err := utils.DecodeParams(parameters, &lambdaConfig)
	if err != nil {
		return err
	}
	_, err = client.GetFunction(context.Background(), &lambda.GetFunctionInput{
		FunctionName: &lambdaConfig.AWSLambdaName,
	})
	if err != nil {
		return err
	}
	return nil
}
