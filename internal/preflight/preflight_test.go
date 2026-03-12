package preflight

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestCheckLocal_RejectsBuildContexts(t *testing.T) {
	root := t.TempDir()
	composePath := filepath.Join(root, "docker-compose.app.yml")
	if err := os.WriteFile(composePath, []byte("services:\n  app:\n    build: .\n"), 0o644); err != nil {
		t.Fatalf("write compose: %v", err)
	}
	envPath := filepath.Join(root, ".env.app")
	if err := os.WriteFile(envPath, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatalf("write env: %v", err)
	}

	cfg := config.Default("demo")
	cfg.App.ComposeFile = composePath
	cfg.App.EnvFile = envPath

	_, errs := CheckLocal(cfg, root, false)
	if len(errs) == 0 {
		t.Fatal("expected build context error")
	}
}
