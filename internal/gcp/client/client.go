package client

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	functionsv2 "cloud.google.com/go/functions/apiv2"
	"cloud.google.com/go/functions/apiv2/functionspb"
	"github.com/falco-talon/falco-talon/configuration"
	"github.com/falco-talon/falco-talon/utils"
	"github.com/googleapis/gax-go/v2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

const functionServiceScope = "https://www.googleapis.com/auth/cloud-platform"

type GCPClient struct {
	functionsClient     GcpFunctionAPI
	functionsClientOnce sync.Once
	httpClient          HTTPClient
	clientOpts          []option.ClientOption
	projectId           string
}

type GCPClientAPI interface {
	GetGcpFunctionClient(context.Context) (GcpFunctionAPI, error)
	ProjectId() string
	HTTPClient() HTTPClient
	SetHTTPClient(httpClient HTTPClient)
	Close() []error
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type GcpFunctionAPI interface {
	GetFunction(ctx context.Context, req *functionspb.GetFunctionRequest, opts ...gax.CallOption) (*functionspb.Function, error)
	Close() error
}

var (
	gcpClient *GCPClient
	once      sync.Once
)

func Init() error {
	if gcpClient != nil {
		return nil
	}

	var initErr error
	once.Do(func() {
		gcpConfig := configuration.GetConfiguration().GcpConfig

		var clientOptions []option.ClientOption
		var creds *google.Credentials
		var err error

		if gcpConfig.CredentialsPath != "" {
			creds, err = google.CredentialsFromJSON(context.Background(), []byte(gcpConfig.CredentialsPath), functionServiceScope)
			if err != nil {
				initErr = fmt.Errorf("unable to load credentials from file: %v", err)
				return
			}
			clientOptions = append(clientOptions, option.WithCredentials(creds))
		} else {
			creds, err = google.FindDefaultCredentials(context.Background(), functionServiceScope)
			if err != nil {
				initErr = fmt.Errorf("unable to find default credentials: %v", err)
				return
			}
			clientOptions = append(clientOptions, option.WithCredentials(creds))
		}

		projectId, err := getProjectID(creds)
		if err != nil {
			initErr = err
			return
		}

		gcpClient = &GCPClient{
			clientOpts: clientOptions,
			projectId:  projectId,
			httpClient: &http.Client{},
		}

		utils.PrintLog("info", utils.LogLine{Message: "GCP client options initialized"})
	})

	return initErr
}

func GetGCPClient() (*GCPClient, error) {
	if gcpClient == nil {
		err := Init()
		if err != nil {
			return nil, err
		}
	}
	return gcpClient, nil
}

func (c *GCPClient) GetGcpFunctionClient(ctx context.Context) (GcpFunctionAPI, error) {
	var err error
	c.functionsClientOnce.Do(func() {
		c.functionsClient, err = functionsv2.NewFunctionClient(ctx, c.clientOpts...)
	})
	if err != nil {
		return nil, err
	}
	return c.functionsClient, nil
}

func (c *GCPClient) ProjectId() string {
	return c.projectId
}

func (c *GCPClient) HTTPClient() HTTPClient {
	return c.httpClient
}

// SetHTTPClient allows the user to set a custom HTTP client
// to be used by the GCP client
// this allows for better testing and control over the HTTP client
func (c *GCPClient) SetHTTPClient(httpClient HTTPClient) {
	c.httpClient = httpClient
}

// Close at the main client level is responsible
// for shutting down all the underlying service clients
func (c *GCPClient) Close() []error {

	var errorList []error

	if c.functionsClient != nil {
		errorList = append(errorList, c.functionsClient.Close())
	}
	return errorList
}

func getProjectID(creds *google.Credentials) (string, error) {
	if creds.ProjectID == "" {
		return "", fmt.Errorf("project ID not available in the credentials, please specify your project ID in the GCP configuration")
	}
	return creds.ProjectID, nil
}
