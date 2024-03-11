package client

import (
	"context"
	"github.com/Falco-Talon/falco-talon/utils"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

type AWSClient struct {
	cfg aws.Config

	mu           sync.Mutex // Protects the fields below
	lambdaClient *lambda.Client
	//s3Client     *s3.Client
}

var (
	awsClient *AWSClient
	once      sync.Once
)

func Init() error {
	var err error
	once.Do(func() {
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return
		}

		awsClient = &AWSClient{
			cfg: cfg,
		}
	})
	return err
}

// GetAWSClient returns the singleton AWSClient instance. Make sure to call Init() before using this function.
func GetAWSClient() *AWSClient {
	return awsClient
}

func (c *AWSClient) LambdaClient() *lambda.Client {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lambdaClient == nil {
		utils.PrintLog("debug", utils.LogLine{Message: "Lazily loading lambda client..."})
		c.lambdaClient = lambda.NewFromConfig(c.cfg)
	}
	return c.lambdaClient
}

//func (c *AWSClient) S3Client() *s3.Client {
//	c.mu.Lock()
//	defer c.mu.Unlock()
//
//	if c.s3Client == nil {
//		c.s3Client = s3.NewFromConfig(c.cfg)
//	}
//	return c.s3Client
//}
