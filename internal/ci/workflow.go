package ci

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
)

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
    uses: "%s"
    permissions:
      actions: read
      contents: read
      security-events: write
    with:
      fail-on-vuln: %t
      upload-sarif: %t
      scan-args: |-
        --recursive
        ./
`, osvScannerWorkflowRef, !continueOnError, shouldUploadSARIF(cfg)))
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
	containerHints = append(containerHints, profile.Dockerfiles...)
	containerHints = append(containerHints, profile.ComposeFiles...)
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

func shouldUploadSARIF(cfg config.Config) bool {
	switch strings.ToLower(strings.TrimSpace(cfg.CI.GitHub.SARIFUploadMode)) {
	case config.CISARIFUploadModeEnabled:
		return true
	case config.CISARIFUploadModeDisabled:
		return false
	}

	if cfg.CI.GitHub.CodeScanningEnabled {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(cfg.CI.GitHub.RepositoryVisibility), config.RepoVisibilityPublic)
}

func sanitizeJobID(v string) string {
	replacer := strings.NewReplacer("/", "_", ".", "_", "-", "_")
	return replacer.Replace(v)
}
