package client

import (
	"sync"

	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/falco-talon/falco-talon/configuration"
)

type MinioClient struct {
	minioClient *minio.Client
}

var (
	minioClient *MinioClient
	once        sync.Once
)

func Init() error {
	if minioClient != nil {
		return nil
	}

	var initErr error

	once.Do(func() {
		config := configuration.GetConfiguration().MinioConfig

		c, err := minio.New(config.Endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(config.AccessKey, config.SecretKey, ""),
			Secure: config.UseSSL,
		})
		if err != nil {
			initErr = err
			return
		}

		minioClient = &MinioClient{
			minioClient: c,
		}
	})

	return initErr
}

func GetClient() *minio.Client {
	return minioClient.minioClient
}
