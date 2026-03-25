package ci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
)

const (
	osvScannerActionRef = "google/osv-scanner-action@v2.3.0"
	trivyActionRef      = "aquasecurity/trivy-action@v0.33.1"
)

type NodeProject struct {
	Path      string
	Package   string
	Framework string
}

type TechProfile struct {
	NodeProjects      []NodeProject
	DotnetProjects    []string
	Dockerfiles       []string
	ComposeFiles      []string
	ExistingWorkflows []string
}

type WorkflowFile struct {
	Name    string
	Path    string
	Content string
}

type ValidationResult struct {
	Missing  []string
	Outdated []string
}

func Preview(root string, cfg config.Config) ([]WorkflowFile, error) {
	return expectedWorkflows(root, cfg)
}

func DetectTech(root string) (TechProfile, error) {
	profile := TechProfile{}

	workflowDir := filepath.Join(root, ".github", "workflows")
	if entries, err := os.ReadDir(workflowDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if isYAML(entry.Name()) {
				profile.ExistingWorkflows = append(profile.ExistingWorkflows, entry.Name())
			}
		}
		slices.Sort(profile.ExistingWorkflows)
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".next" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		switch {
		case d.Name() == "package.json":
			project, ok := detectNodeProject(path, rel)
			if ok {
				profile.NodeProjects = append(profile.NodeProjects, project)
			}
		case strings.HasSuffix(d.Name(), ".csproj"):
			profile.DotnetProjects = append(profile.DotnetProjects, filepath.ToSlash(rel))
		case strings.HasPrefix(d.Name(), "Dockerfile"):
			profile.Dockerfiles = append(profile.Dockerfiles, filepath.ToSlash(rel))
		case d.Name() == "docker-compose.yml" || d.Name() == "docker-compose.yaml" || d.Name() == "compose.yml" || d.Name() == "compose.yaml":
			profile.ComposeFiles = append(profile.ComposeFiles, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return TechProfile{}, err
	}

	slices.SortFunc(profile.NodeProjects, func(a, b NodeProject) int { return strings.Compare(a.Path, b.Path) })
	slices.Sort(profile.DotnetProjects)
	slices.Sort(profile.Dockerfiles)
	slices.Sort(profile.ComposeFiles)
	return profile, nil
}

func Generate(root string, cfg config.Config) ([]string, error) {
	workflows, err := expectedWorkflows(root, cfg)
	if err != nil {
		return nil, err
	}
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workflow directory: %w", err)
	}

	written := make([]string, 0, len(workflows))
	for _, wf := range workflows {
		if err := os.WriteFile(wf.Path, []byte(wf.Content), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", wf.Path, err)
		}
		written = append(written, wf.Path)
	}
	return written, nil
}

func Validate(root string, cfg config.Config) (ValidationResult, error) {
	workflows, err := expectedWorkflows(root, cfg)
	if err != nil {
		return ValidationResult{}, err
	}

	result := ValidationResult{}
	for _, wf := range workflows {
		raw, err := os.ReadFile(wf.Path)
		if err != nil {
			if os.IsNotExist(err) {
				result.Missing = append(result.Missing, wf.Name)
				continue
			}
			return ValidationResult{}, fmt.Errorf("read %s: %w", wf.Path, err)
		}
		if string(raw) != wf.Content {
			result.Outdated = append(result.Outdated, wf.Name)
		}
	}
	return result, nil
}

func expectedWorkflows(root string, cfg config.Config) ([]WorkflowFile, error) {
	profile, err := DetectTech(root)
	if err != nil {
		return nil, err
	}
	workflowDir := filepath.Join(root, ".github", "workflows")
	workflows := make([]WorkflowFile, 0, 4)

	if cfg.CI.Scans.Dependency || cfg.CI.Scans.License || cfg.CI.Scans.OSV {
		workflows = append(workflows, WorkflowFile{
			Name:    "security-dependencies.yml",
			Path:    filepath.Join(workflowDir, "security-dependencies.yml"),
			Content: buildDependencyWorkflow(cfg, profile),
		})
	}
	if cfg.CI.Scans.Image {
		workflows = append(workflows, WorkflowFile{
			Name:    "security-containers.yml",
			Path:    filepath.Join(workflowDir, "security-containers.yml"),
			Content: buildContainerWorkflow(cfg, profile),
		})
	}
	if cfg.CI.Scans.SBOM {
		workflows = append(workflows, WorkflowFile{
			Name:    "security-sbom.yml",
			Path:    filepath.Join(workflowDir, "security-sbom.yml"),
			Content: buildSBOMWorkflow(cfg, profile),
		})
	}
	if cfg.CI.Scans.Secrets {
		workflows = append(workflows, WorkflowFile{
			Name:    "security-secrets.yml",
			Path:    filepath.Join(workflowDir, "security-secrets.yml"),
			Content: buildSecretsWorkflow(cfg),
		})
	}

	return workflows, nil
}

func buildDependencyWorkflow(cfg config.Config, profile TechProfile) string {
	jobs := []string{}
	continueOnError := workflowContinueOnError(cfg)
	if len(profile.NodeProjects) > 0 && cfg.CI.Scans.Dependency {
		for idx, project := range profile.NodeProjects {
			jobName := sanitizeJobID(fmt.Sprintf("node_%d_%s", idx, project.Path))
			jobs = append(jobs, fmt.Sprintf(`
  %s:
    name: Node dependency scan (%s)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: %s/package-lock.json
      - name: Install dependencies
        working-directory: %s
        run: npm ci
      - name: npm audit
        continue-on-error: %t
        working-directory: %s
        run: npm audit --audit-level=high
`, jobName, project.Path, project.Path, project.Path, continueOnError, project.Path))
		}
	}
	if len(profile.DotnetProjects) > 0 && cfg.CI.Scans.Dependency {
		for idx, csproj := range profile.DotnetProjects {
			jobName := sanitizeJobID(fmt.Sprintf("dotnet_%d_%s", idx, csproj))
			projectDir := filepath.ToSlash(filepath.Dir(csproj))
			jobs = append(jobs, fmt.Sprintf(`
  %s:
    name: .NET vulnerability scan (%s)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 9.0.x
      - name: Restore
        working-directory: %s
        run: dotnet restore %s
      - name: Vulnerable packages
        continue-on-error: %t
        working-directory: %s
        run: dotnet list %s package --vulnerable --include-transitive
`, jobName, csproj, projectDir, filepath.Base(csproj), continueOnError, projectDir, filepath.Base(csproj)))
		}
	}
	if cfg.CI.Scans.OSV {
		jobs = append(jobs, fmt.Sprintf(`
  osv:
    name: OSV scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: %s
        continue-on-error: %t
        with:
          scan-args: -r .
`, osvScannerActionRef, continueOnError))
	}
	if cfg.CI.Scans.License {
		jobs = append(jobs, fmt.Sprintf(`
  license:
    name: License inventory
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: %s
        continue-on-error: %t
        with:
          scan-type: fs
          scan-ref: .
          scanners: license
          format: table
          output: trivy-license.txt
      - uses: actions/upload-artifact@v4
        with:
          name: license-report
          path: trivy-license.txt
`, trivyActionRef, continueOnError))
	}
	if len(jobs) == 0 {
		jobs = append(jobs, `
  noop:
    runs-on: ubuntu-latest
    steps:
      - run: echo "No dependency-aware targets detected. Update resistack config or repo layout."
`)
	}

	return workflowHeader("Security Dependencies", cfg) + strings.Join(jobs, "")
}

func buildContainerWorkflow(cfg config.Config, profile TechProfile) string {
	continueOnError := workflowContinueOnError(cfg)
	containerHints := []string{}
	for _, dockerfile := range profile.Dockerfiles {
		containerHints = append(containerHints, dockerfile)
	}
	for _, composeFile := range profile.ComposeFiles {
		containerHints = append(containerHints, composeFile)
	}
	targets := "."
	if len(containerHints) > 0 {
		targets = strings.Join(containerHints, ", ")
	}

	jobs := fmt.Sprintf(`
  containers:
    name: Container and image scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: %s
        continue-on-error: %t
        with:
          scan-type: fs
          scan-ref: .
          format: table
          severity: CRITICAL,HIGH,MEDIUM
          output: trivy-containers.txt
      - name: Document detected container inputs
        run: |
          cat <<'EOF' > detected-container-inputs.txt
          Detected container inputs: %s
          EOF
      - uses: actions/upload-artifact@v4
        with:
          name: container-scan
          path: |
            trivy-containers.txt
            detected-container-inputs.txt
`, trivyActionRef, continueOnError, targets)

	return workflowHeader("Security Containers", cfg) + jobs
}

func buildSBOMWorkflow(cfg config.Config, profile TechProfile) string {
	sbomTargets := []string{"."}
	if len(profile.Dockerfiles) > 0 {
		sbomTargets = append(sbomTargets, profile.Dockerfiles...)
	}
	continueOnError := workflowContinueOnError(cfg)
	jobs := fmt.Sprintf(`
  sbom:
    name: SBOM generation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        continue-on-error: %t
        with:
          path: .
          format: cyclonedx-json
          output-file: sbom.cdx.json
      - name: Annotate SBOM scope
        run: |
          cat <<'EOF' > sbom-scope.txt
          SBOM scope: %s
          EOF
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            sbom.cdx.json
            sbom-scope.txt
`, continueOnError, strings.Join(sbomTargets, ", "))

	return workflowHeader("Security SBOM", cfg) + jobs
}

func buildSecretsWorkflow(cfg config.Config) string {
	continueOnError := workflowContinueOnError(cfg)
	jobs := fmt.Sprintf(`
  secrets:
    name: Secret scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gitleaks/gitleaks-action@v2
        continue-on-error: %t
      - name: Archive findings placeholder
        run: echo "See gitleaks annotations for detected secrets." > gitleaks-summary.txt
      - uses: actions/upload-artifact@v4
        with:
          name: secret-scan
          path: gitleaks-summary.txt
`, continueOnError)

	return workflowHeader("Security Secrets", cfg) + jobs
}

func workflowHeader(name string, cfg config.Config) string {
	return fmt.Sprintf(`name: %s

on:
  pull_request:
  push:
    branches:
      - main
      - master
  schedule:
    - cron: '%s'

permissions:
  contents: read
  pull-requests: write

jobs:
`, name, cfg.CI.Schedule)
}

func workflowContinueOnError(cfg config.Config) bool {
	return strings.EqualFold(strings.TrimSpace(cfg.CI.Mode), config.CIModeWarnOnly)
}

func sanitizeJobID(v string) string {
	replacer := strings.NewReplacer("/", "_", ".", "_", "-", "_")
	return replacer.Replace(v)
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

func detectNodeProject(absPath string, relPath string) (NodeProject, bool) {
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return NodeProject{}, false
	}
	var pkg struct {
		Name         string            `json:"name"`
		Dependencies map[string]string `json:"dependencies"`
		DevDeps      map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return NodeProject{}, false
	}

	framework := "node"
	if _, ok := pkg.Dependencies["next"]; ok {
		framework = "nextjs"
	} else if _, ok := pkg.DevDeps["next"]; ok {
		framework = "nextjs"
	}

	projectDir := filepath.ToSlash(filepath.Dir(relPath))
	return NodeProject{
		Path:      projectDir,
		Package:   pkg.Name,
		Framework: framework,
	}, true
}
