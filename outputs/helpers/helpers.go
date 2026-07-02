package helpers

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/falcosecurity/falco-talon/internal/models"
)

const keyTimestampLayout = "2006-01-02T15-04-05Z"

// BuildObjectKey returns a timestamped, filesystem-safe key used by the outputs
// (file, S3, GCS, MinIO) to store the artifact carried by data. The key is
// prefixed with the current time and derived from the well-known objects
// (namespace/pod, then hostname); otherwise it falls back to every object
// value except "file", in a deterministic (sorted) order.
func BuildObjectKey(data *models.Data) string {
	timestamp := time.Now().Format(keyTimestampLayout)
	name := strings.ReplaceAll(data.Name, "/", "_")

	switch {
	case data.Objects["namespace"] != "" && data.Objects["pod"] != "":
		return fmt.Sprintf("%v_%v_%v_%v", timestamp, data.Objects["namespace"], data.Objects["pod"], name)
	case data.Objects["hostname"] != "":
		return fmt.Sprintf("%v_%v_%v", timestamp, data.Objects["hostname"], name)
	default:
		keys := make([]string, 0, len(data.Objects))
		for k := range data.Objects {
			if k != "file" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)

		var builder strings.Builder
		for _, k := range keys {
			builder.WriteString(data.Objects[k])
			builder.WriteString("_")
		}
		return fmt.Sprintf("%v_%v%v", timestamp, builder.String(), name)
	}
}
