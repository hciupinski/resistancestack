package scaffold

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateWritesFiles(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "resistack.local.yaml")

	result, err := Generate(Options{
		Root:        root,
		ProjectName: "demo",
		ConfigPath:  cfgPath,
		Force:       false,
		WithCI:      true,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if len(result.Written) < 3 {
		t.Fatalf("expected at least 3 written files, got %d", len(result.Written))
	}

	required := []string{
		cfgPath,
		filepath.Join(root, "docker-compose.app.yml"),
		filepath.Join(root, ".env.app.example"),
		filepath.Join(root, ".github", "workflows", "security.yml"),
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}
}

func TestGenerateSkipsExistingWithoutForce(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "resistack.local.yaml")
	if err := os.WriteFile(cfgPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write seed config: %v", err)
	}

	result, err := Generate(Options{
		Root:        root,
		ProjectName: "demo",
		ConfigPath:  cfgPath,
		Force:       false,
		WithCI:      false,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	foundSkip := false
	for _, path := range result.Skipped {
		if path == cfgPath {
			foundSkip = true
			break
		}
	}
	if !foundSkip {
		t.Fatal("expected config file to be skipped")
	}
}
