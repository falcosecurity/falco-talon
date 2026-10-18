package elasticsearch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExampleOnlyDocumentsElasticsearchNotifier(t *testing.T) {
	if strings.Contains(Example, "slack:") {
		t.Fatalf("expected elasticsearch example not to include unrelated slack notifier config, got:\n%s", Example)
	}
	if strings.Count(Example, "notifiers:") != 1 {
		t.Fatalf("expected elasticsearch example to contain a single notifiers block, got:\n%s", Example)
	}
}

func TestInitCreatesMissingIndexTemplate(t *testing.T) {
	previous := parameters
	t.Cleanup(func() { parameters = previous })

	created := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != indexTemplate {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			var body struct {
				Template struct {
					Mappings struct {
						Properties map[string]struct{ Type string }
					}
				}
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode index template: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := body.Template.Mappings.Properties["error"].Type; got != "text" {
				t.Errorf("error mapping type = %q, want text", got)
			}
			created <- true
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	if err := Register().Init(map[string]any{"url": server.URL}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(created) != 1 {
		t.Fatal("Init did not create the missing index template")
	}
}
