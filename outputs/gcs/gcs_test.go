// SPDX-License-Identifier: Apache-2.0

package gcs

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

func TestRunWithClientReportsUploadResult(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || !strings.Contains(r.URL.Path, "/b/artifacts/o") {
					t.Errorf("unexpected upload request: %s %s", r.Method, r.URL)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upload: %v", err)
				}
				if !strings.Contains(string(body), "pod log contents") {
					t.Errorf("upload did not contain artifact: %s", body)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = io.WriteString(w, `{"bucket":"artifacts","name":"log","size":"16"}`)
				} else {
					_, _ = io.WriteString(w, `{"error":{"message":"upload rejected"}}`)
				}
			}))
			defer server.Close()

			client, err := storage.NewClient(context.Background(), option.WithEndpoint(server.URL), option.WithoutAuthentication())
			if err != nil {
				t.Fatalf("create storage client: %v", err)
			}
			defer func() { _ = client.Close() }()

			output := &rules.Output{Parameters: map[string]any{"bucket": "artifacts", "prefix": "logs"}}
			data := &models.Data{Name: "log", Objects: map[string]string{"namespace": "default", "pod": "demo"}, Bytes: []byte("pod log contents")}
			log, err := Register().RunWithClient(client, output, data)
			if status == http.StatusOK {
				if err != nil || log.Status != utils.SuccessStr {
					t.Fatalf("successful upload: log=%+v, err=%v", log, err)
				}
				return
			}

			var apiErr *googleapi.Error
			if !errors.As(err, &apiErr) || apiErr.Code != status {
				t.Fatalf("expected upload error %d, got log=%+v, err=%v", status, log, err)
			}
			if log.Status != utils.FailureStr || log.Error == "" {
				t.Fatalf("expected failed output log, got %+v", log)
			}
		})
	}
}
