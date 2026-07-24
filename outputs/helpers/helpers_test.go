package helpers

import (
	"strings"
	"testing"

	"github.com/falcosecurity/falco-talon/internal/models"
)

func TestBuildObjectKey(t *testing.T) {
	const ts = "_" // separator sanity marker, keys always contain underscores

	t.Run("namespace and pod", func(t *testing.T) {
		key := BuildObjectKey(&models.Data{
			Name:    "logs/app.txt",
			Objects: map[string]string{"namespace": "prod", "pod": "nginx"},
		})
		// timestamp_namespace_pod_name, with "/" replaced by "_" in the name
		if !strings.HasSuffix(key, "_prod_nginx_logs_app.txt") {
			t.Errorf("unexpected key: %q", key)
		}
	})

	t.Run("hostname", func(t *testing.T) {
		key := BuildObjectKey(&models.Data{
			Name:    "capture.pcap",
			Objects: map[string]string{"hostname": "node-1"},
		})
		if !strings.HasSuffix(key, "_node-1_capture.pcap") {
			t.Errorf("unexpected key: %q", key)
		}
	})

	t.Run("default is deterministic and sorted, excluding file", func(t *testing.T) {
		objects := map[string]string{"zeta": "z", "alpha": "a", "file": "ignored"}
		first := BuildObjectKey(&models.Data{Name: "n", Objects: objects})
		second := BuildObjectKey(&models.Data{Name: "n", Objects: objects})

		// keys are sorted (alpha before zeta) and "file" is excluded
		if !strings.Contains(first, "_a_z_") {
			t.Errorf("expected sorted values a then z, got: %q", first)
		}
		if strings.Contains(first, "ignored") {
			t.Errorf("the \"file\" object must be excluded, got: %q", first)
		}
		// deterministic: the value part (everything after the timestamp) is stable
		if first[strings.Index(first, "_"):] != second[strings.Index(second, "_"):] {
			t.Errorf("key value part is not deterministic: %q vs %q", first, second)
		}
	})
}
