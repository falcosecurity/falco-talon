package client

import (
	"context"
	"sync"

	"github.com/falco-talon/falco-talon/configuration"
	"github.com/falco-talon/falco-talon/utils"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type AWSClient struct {
	lambdaClient *lambda.Client
	imdsClient   *imds.Client
	// s3Client     *s3.Client
	cfg aws.Config
}

var (
	awsClient *AWSClient
	once      sync.Once
)

func Init() error {
	var initErr error

	awsConfig := configuration.GetConfiguration().AwsConfig

	once.Do(func() {
		var cfg aws.Config
		var err error

		if awsConfig.AccessKey != "" && awsConfig.SecretKey != "" && awsConfig.Region != "" {
			cfg, err = config.LoadDefaultConfig(
				context.TODO(),
				config.WithRegion(awsConfig.Region),
				config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(awsConfig.AccessKey, awsConfig.SecretKey, "")),
			)
		} else {
			cfg, err = config.LoadDefaultConfig(context.TODO())
		}
		if err != nil {
			initErr = err
			return
		}

		if awsConfig.RoleArn != "" {
			stsClient := sts.NewFromConfig(cfg)
			assumeRoleOptions := func(o *stscreds.AssumeRoleOptions) {
				if awsConfig.ExternalID != "" {
					o.ExternalID = aws.String(awsConfig.ExternalID)
				}
			}
			provider := stscreds.NewAssumeRoleProvider(stsClient, awsConfig.RoleArn, assumeRoleOptions)
			cfg.Credentials = aws.NewCredentialsCache(provider)
		}

		// Perform a dry run to validate credentials
		stsClient := sts.NewFromConfig(cfg)
		_, err = stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
		if err != nil {
			initErr = err
			return
		}

		awsClient = &AWSClient{
			cfg: cfg,
		}
	})

	return initErr
}

func GetAWSClient() *AWSClient {
	return awsClient
}

func (c *AWSClient) GetLambdaClient() *lambda.Client {
	if c.lambdaClient == nil {
		utils.PrintLog("warning", utils.LogLine{Message: "Lazily loading AWS Lambda client..."})
		c.lambdaClient = lambda.NewFromConfig(c.cfg)
	}
	return c.lambdaClient
}

func (c *AWSClient) GetImds() *imds.Client {
	if c.imdsClient == nil {
		utils.PrintLog("warning", utils.LogLine{Message: "Lazily loading AWS IMDS client..."})
		c.imdsClient = imds.NewFromConfig(c.cfg)
	}
	return c.imdsClient
}
