package configuration

import (
	"os"
	"path/filepath"
	"testing"
)

func resetConfigForTest() {
	config = new(Configuration)
}

func TestCreateConfigurationAllowsOverridingOtelTimeoutFromFile(t *testing.T) {
	t.Cleanup(resetConfigForTest)
	resetConfigForTest()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte(`
otel:
  timeout: 42
`), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg := CreateConfiguration(configFile)

	if cfg.Otel.Timeout != 42 {
		t.Fatalf("expected otel timeout from config file to be applied, got %d", cfg.Otel.Timeout)
	}
}

func TestCreateConfigurationAllowsOverridingOtelTimeoutFromEnv(t *testing.T) {
	t.Cleanup(resetConfigForTest)
	resetConfigForTest()
	t.Setenv("OTEL_TIMEOUT", "37")

	cfg := CreateConfiguration("")

	if cfg.Otel.Timeout != 37 {
		t.Fatalf("expected otel timeout from env to be applied, got %d", cfg.Otel.Timeout)
	}
}
