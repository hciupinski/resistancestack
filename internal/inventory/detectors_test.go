package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectComposeFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:{}\n"), 0o644); err != nil {
		t.Fatalf("write compose: %v", err)
	}

	files, err := DetectComposeFiles(root, nil)
	if err != nil {
		t.Fatalf("detect compose: %v", err)
	}
	if len(files) != 1 || files[0] != "docker-compose.yml" {
		t.Fatalf("unexpected compose files: %#v", files)
	}
}

func TestDetectNginxPaths(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "infra", "nginx")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir nginx path: %v", err)
	}

	paths, err := DetectNginxPaths(root, nil)
	if err != nil {
		t.Fatalf("detect nginx: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected nginx path detection")
	}
}

func TestDetectSystemdUnits(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "deploy", "systemd", "myapp.service")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir systemd: %v", err)
	}
	if err := os.WriteFile(path, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatalf("write unit: %v", err)
	}

	units, err := DetectSystemdUnits(root, []string{"myapp"})
	if err != nil {
		t.Fatalf("detect units: %v", err)
	}
	if len(units) != 1 || units[0] != "deploy/systemd/myapp.service" {
		t.Fatalf("unexpected units: %#v", units)
	}
}

func TestDetectGitHubWorkflows(t *testing.T) {
	root := t.TempDir()
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir workflows: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "deploy.yml"), []byte("name: deploy\n"), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	workflows, err := DetectGitHubWorkflows(root)
	if err != nil {
		t.Fatalf("detect workflows: %v", err)
	}
	if len(workflows) != 1 || workflows[0] != ".github/workflows/deploy.yml" {
		t.Fatalf("unexpected workflows: %#v", workflows)
	}
}
