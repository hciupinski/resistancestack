package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestDetectTech_MixedRepo(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ui"), 0o755); err != nil {
		t.Fatalf("mkdir ui: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "ui", "package.json"), []byte(`{"name":"ui","dependencies":{"next":"15.0.0"}}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "src", "Public.Api"), 0o755); err != nil {
		t.Fatalf("mkdir api: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "Public.Api", "Public.Api.csproj"), []byte(`<Project />`), 0o644); err != nil {
		t.Fatalf("write csproj: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	profile, err := DetectTech(root)
	if err != nil {
		t.Fatalf("detect tech: %v", err)
	}
	if len(profile.NodeProjects) != 1 || profile.NodeProjects[0].Path != "ui" {
		t.Fatalf("unexpected node projects: %#v", profile.NodeProjects)
	}
	if len(profile.DotnetProjects) != 1 || profile.DotnetProjects[0] != "src/Public.Api/Public.Api.csproj" {
		t.Fatalf("unexpected dotnet projects: %#v", profile.DotnetProjects)
	}
	if len(profile.Dockerfiles) != 1 || profile.Dockerfiles[0] != "Dockerfile" {
		t.Fatalf("unexpected dockerfiles: %#v", profile.Dockerfiles)
	}
}

func TestGenerate_CreatesStandaloneSecurityWorkflows(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ui"), 0o755); err != nil {
		t.Fatalf("mkdir ui: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "ui", "package.json"), []byte(`{"name":"ui","dependencies":{"next":"15.0.0"}}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "src", "Public.Api"), 0o755); err != nil {
		t.Fatalf("mkdir api: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "Public.Api", "Public.Api.csproj"), []byte(`<Project />`), 0o644); err != nil {
		t.Fatalf("write csproj: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatalf("mkdir workflows: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "workflows", "deploy.yml"), []byte("name: deploy\n"), 0o644); err != nil {
		t.Fatalf("write deploy workflow: %v", err)
	}

	cfg := config.Default("demo")
	paths, err := Generate(root, cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(paths) != 4 {
		t.Fatalf("expected 4 workflows, got %d", len(paths))
	}
	if _, err := os.Stat(filepath.Join(root, ".github", "workflows", "deploy.yml")); err != nil {
		t.Fatalf("existing deploy workflow should remain untouched: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "security-dependencies.yml"))
	if err != nil {
		t.Fatalf("read dependencies workflow: %v", err)
	}
	if !strings.Contains(string(content), "npm audit") || !strings.Contains(string(content), "dotnet list") {
		t.Fatalf("expected mixed repo scans in workflow, got:\n%s", string(content))
	}
}

func TestValidate_FindsOutdatedWorkflow(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatalf("mkdir workflows: %v", err)
	}
	cfg := config.Default("demo")
	if err := os.WriteFile(filepath.Join(root, ".github", "workflows", "security-secrets.yml"), []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale workflow: %v", err)
	}

	result, err := Validate(root, cfg)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(result.Outdated) == 0 && len(result.Missing) == 0 {
		t.Fatal("expected missing or outdated workflows")
	}
}
