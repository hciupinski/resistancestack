package ci

import (
	"fmt"
	"os"
	"path/filepath"
)

const securityWorkflow = `name: Security Checks

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          scan-ref: .
          format: table
          exit-code: '1'
          severity: CRITICAL,HIGH

  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with:
          config: p/security-audit

  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gitleaks/gitleaks-action@v2

  osv-scanner:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google/osv-scanner-action/osv-scanner-action@v2
        with:
          scan-args: -r .

  zap-baseline:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - name: ZAP Baseline placeholder
        run: |
          echo "Configure staging target URL and replace this step with zap-baseline run."
`

func EnsureSecurityWorkflow(root string) (string, bool, error) {
	workflowDir := filepath.Join(root, ".github", "workflows")
	path := filepath.Join(workflowDir, "security.yml")

	if _, err := os.Stat(path); err == nil {
		return path, false, nil
	}

	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		return "", false, fmt.Errorf("create workflow directory: %w", err)
	}

	if err := os.WriteFile(path, []byte(securityWorkflow), 0o644); err != nil {
		return "", false, fmt.Errorf("write workflow: %w", err)
	}

	return path, true, nil
}
