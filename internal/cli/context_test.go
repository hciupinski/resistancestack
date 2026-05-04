package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestConfigBackedCommandsAcceptEnvFlag(t *testing.T) {
	root := t.TempDir()
	configPath := writeValidConfig(t, root)

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "inventory",
			args: []string{"inventory", "--config", configPath, "--env", "prod"},
		},
		{
			name: "audit",
			args: []string{"audit", "--config", configPath, "--env", "prod", "--dry-run"},
		},
		{
			name: "apply",
			args: []string{"apply", "--config", configPath, "--env", "prod", "--dry-run", "host-hardening"},
		},
		{
			name: "status",
			args: []string{"status", "--config", configPath, "--env", "prod"},
		},
		{
			name: "deploy-user check",
			args: []string{"deploy-user", "check", "--config", configPath, "--env", "prod"},
		},
		{
			name: "deploy-user bootstrap",
			args: []string{"deploy-user", "bootstrap", "--config", configPath, "--env", "prod", "--dry-run"},
		},
		{
			name: "ci generate",
			args: []string{"ci", "generate", "--config", configPath, "--env", "prod"},
		},
		{
			name: "ci validate",
			args: []string{"ci", "validate", "--config", configPath, "--env", "prod"},
		},
		{
			name: "observability enable",
			args: []string{"observability", "enable", "--config", configPath, "--env", "prod", "--dry-run"},
		},
		{
			name: "observability disable",
			args: []string{"observability", "disable", "--config", configPath, "--env", "prod"},
		},
		{
			name: "rollback host",
			args: []string{"rollback", "host", "--config", configPath, "--env", "prod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Run(tt.args, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil {
				t.Fatal("expected missing overlay error")
			}
			if got := err.Error(); !strings.Contains(got, `environment overlay "prod" not found`) {
				t.Fatalf("unexpected error %q", got)
			}
		})
	}
}

func TestRunApplyCobra_AcceptsPersistentFlagsAfterModules(t *testing.T) {
	root := t.TempDir()
	configPath := writeValidConfig(t, root)

	err := Run([]string{"apply", "host-hardening", "--env", "prod", "--dry-run", "--config", configPath}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected missing overlay error")
	}
	if got := err.Error(); !strings.Contains(got, `environment overlay "prod" not found`) {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestRun_UsesConfigFromEnvironment(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "from-env.yaml")
	t.Setenv("RESISTACK_CONFIG", configPath)

	var out bytes.Buffer
	if err := Run([]string{"init", "env-demo"}, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("expected config from env to be created: %v", err)
	}
	if got := out.String(); !strings.Contains(got, configPath) {
		t.Fatalf("expected output to mention env config path, got %q", got)
	}
}

func TestLoadContext_OutputOverrideUpdatesReportingFormat(t *testing.T) {
	root := t.TempDir()
	configPath := writeValidConfig(t, root)

	ctx, err := loadContext(ConfigSelection{ConfigPath: configPath, OutputFormat: config.FormatJSON}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("load context: %v", err)
	}
	if ctx.Config.Reporting.Format != config.FormatJSON {
		t.Fatalf("expected reporting format override, got %q", ctx.Config.Reporting.Format)
	}
}

func TestLoadContext_WithEnvPrintsSummaryAndLoadsMergedConfig(t *testing.T) {
	root := t.TempDir()
	configPath := writeValidConfig(t, root)
	overlayPath := filepath.Join(root, "resistack.prod.yaml")
	overlay := `server:
  host: 203.0.113.20
  private_key_path: ~/.ssh/id_prod
host_hardening:
  ufw_policy:
    admin_allowlist:
      - 198.51.100.77/32
`
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	ctx, err := loadContext(ConfigSelection{ConfigPath: configPath, Env: "prod"}, &out, &errOut)
	if err != nil {
		t.Fatalf("load context: %v", err)
	}
	if ctx.Env != "prod" {
		t.Fatalf("unexpected env %q", ctx.Env)
	}
	if ctx.OverlayPath != overlayPath {
		t.Fatalf("unexpected overlay path %q", ctx.OverlayPath)
	}
	if ctx.Config.Server.Host != "203.0.113.20" {
		t.Fatalf("unexpected host %q", ctx.Config.Server.Host)
	}
	if len(ctx.Config.HostHardening.UFWPolicy.AdminAllowlist) != 1 || ctx.Config.HostHardening.UFWPolicy.AdminAllowlist[0] != "198.51.100.77/32" {
		t.Fatalf("unexpected allowlist %#v", ctx.Config.HostHardening.UFWPolicy.AdminAllowlist)
	}
	if got := errOut.String(); !strings.Contains(got, `using environment "prod"`) || !strings.Contains(got, configPath) || !strings.Contains(got, overlayPath) {
		t.Fatalf("unexpected stderr %q", got)
	}
}

func TestLoadContext_WithoutEnvDoesNotPrintSelectionSummary(t *testing.T) {
	root := t.TempDir()
	configPath := writeValidConfig(t, root)

	var out bytes.Buffer
	var errOut bytes.Buffer
	ctx, err := loadContext(ConfigSelection{ConfigPath: configPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("load context: %v", err)
	}
	if ctx.Env != "" {
		t.Fatalf("unexpected env %q", ctx.Env)
	}
	if ctx.OverlayPath != "" {
		t.Fatalf("unexpected overlay path %q", ctx.OverlayPath)
	}
	if got := errOut.String(); got != "" {
		t.Fatalf("expected no stderr output, got %q", got)
	}
}

func TestRunRollback_UsesEnvOverlayDuringValidation(t *testing.T) {
	root := t.TempDir()
	configPath := writeValidConfig(t, root)
	overlayPath := filepath.Join(root, "resistack.prod.yaml")
	overlay := `server:
  host: ""
`
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	var errOut bytes.Buffer
	err := Run([]string{"rollback", "host", "--config", configPath, "--env", "prod"}, &bytes.Buffer{}, &errOut)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if got := err.Error(); got != "configuration is invalid" {
		t.Fatalf("unexpected error %q", got)
	}
	if got := errOut.String(); !strings.Contains(got, "validation error: server.host is required") {
		t.Fatalf("unexpected stderr %q", got)
	}
}

func writeValidConfig(t *testing.T, root string) string {
	t.Helper()

	path := filepath.Join(root, "resistack.yaml")
	cfg := config.Default("demo")
	cfg.Server.Host = "198.51.100.10"
	cfg.HostHardening.UFWPolicy.AdminAllowlist = []string{"203.0.113.10/32"}
	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return path
}
