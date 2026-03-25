package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
	"gopkg.in/yaml.v3"
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

func TestPreview_GeneratedWorkflowsAreValidYAMLAndUseResolvableActionRefs(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(root, "ui", "Dockerfile"), []byte("FROM node:22\n"), 0o644); err != nil {
		t.Fatalf("write dockerfile: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "infra", "docker", "prod"), 0o755); err != nil {
		t.Fatalf("mkdir compose dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "infra", "docker", "prod", "docker-compose.yml"), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatalf("write compose file: %v", err)
	}

	cfg := config.Default("demo")
	workflows, err := Preview(root, cfg)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	for _, wf := range workflows {
		var parsed yaml.Node
		if err := yaml.Unmarshal([]byte(wf.Content), &parsed); err != nil {
			t.Fatalf("workflow %s should be valid yaml: %v\n%s", wf.Name, err, wf.Content)
		}
	}

	joined := joinWorkflowContent(workflows)
	for _, expected := range []string{
		osvScannerWorkflowRef,
		trivyActionRef,
		"fail-on-vuln: false",
		"upload-sarif: false",
		"run: |\n          cat <<'EOF' > detected-container-inputs.txt",
		"run: |\n          cat <<'EOF' > sbom-scope.txt",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected %q in generated workflows", expected)
		}
	}
	if strings.Contains(joined, "google/osv-scanner-action/osv-scanner-action@v2") {
		t.Fatal("expected broken OSV action ref to be removed")
	}
	if strings.Contains(joined, "google/osv-scanner-action@v2.3.0") {
		t.Fatal("expected OSV reusable workflow ref instead of action ref")
	}
	if strings.Contains(joined, "aquasecurity/trivy-action@0.33.1") {
		t.Fatal("expected trivy action ref to include the v prefix")
	}
}

func TestPreview_PublicRepoEnablesSARIFUploadInAutoMode(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default("demo")
	cfg.CI.GitHub.RepositoryVisibility = config.RepoVisibilityPublic
	cfg.CI.GitHub.CodeScanningEnabled = false
	cfg.CI.GitHub.SARIFUploadMode = config.CISARIFUploadModeAuto

	workflows, err := Preview(root, cfg)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	joined := joinWorkflowContent(workflows)
	if !strings.Contains(joined, "upload-sarif: true") {
		t.Fatal("expected SARIF upload enabled for public repositories in auto mode")
	}
}

func TestPreview_CodeScanningEnabledEnablesSARIFUploadInAutoMode(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default("demo")
	cfg.CI.GitHub.RepositoryVisibility = config.RepoVisibilityPrivate
	cfg.CI.GitHub.CodeScanningEnabled = true
	cfg.CI.GitHub.SARIFUploadMode = config.CISARIFUploadModeAuto

	workflows, err := Preview(root, cfg)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	joined := joinWorkflowContent(workflows)
	if !strings.Contains(joined, "upload-sarif: true") {
		t.Fatal("expected SARIF upload enabled when code scanning is explicitly enabled")
	}
}

func TestPreview_DisabledSARIFModeForcesUploadOff(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default("demo")
	cfg.CI.GitHub.RepositoryVisibility = config.RepoVisibilityPublic
	cfg.CI.GitHub.CodeScanningEnabled = true
	cfg.CI.GitHub.SARIFUploadMode = config.CISARIFUploadModeDisabled

	workflows, err := Preview(root, cfg)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	joined := joinWorkflowContent(workflows)
	if !strings.Contains(joined, "upload-sarif: false") {
		t.Fatal("expected disabled SARIF mode to force upload off")
	}
}

func TestPreview_EnabledSARIFModeForcesUploadOn(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default("demo")
	cfg.CI.GitHub.RepositoryVisibility = config.RepoVisibilityUnknown
	cfg.CI.GitHub.CodeScanningEnabled = false
	cfg.CI.GitHub.SARIFUploadMode = config.CISARIFUploadModeEnabled

	workflows, err := Preview(root, cfg)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	joined := joinWorkflowContent(workflows)
	if !strings.Contains(joined, "upload-sarif: true") {
		t.Fatal("expected enabled SARIF mode to force upload on")
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

func joinWorkflowContent(workflows []WorkflowFile) string {
	parts := make([]string, 0, len(workflows))
	for _, wf := range workflows {
		parts = append(parts, wf.Content)
	}
	return strings.Join(parts, "\n---\n")
}
