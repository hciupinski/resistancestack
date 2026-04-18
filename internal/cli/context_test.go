package cli

import (
	"bytes"
	"io"
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
		run  func([]string, io.Writer, io.Writer) error
		args []string
	}{
		{
			name: "inventory",
			run:  runInventory,
			args: []string{"--config", configPath, "--env", "prod"},
		},
		{
			name: "audit",
			run:  runAudit,
			args: []string{"--config", configPath, "--env", "prod", "--dry-run"},
		},
		{
			name: "apply",
			run:  runApply,
			args: []string{"--config", configPath, "--env", "prod", "--dry-run", "host-hardening"},
		},
		{
			name: "status",
			run:  runStatus,
			args: []string{"--config", configPath, "--env", "prod"},
		},
		{
			name: "ci generate",
			run:  runCI,
			args: []string{"generate", "--config", configPath, "--env", "prod"},
		},
		{
			name: "ci validate",
			run:  runCI,
			args: []string{"validate", "--config", configPath, "--env", "prod"},
		},
		{
			name: "observability enable",
			run:  runObservability,
			args: []string{"enable", "--config", configPath, "--env", "prod", "--dry-run"},
		},
		{
			name: "observability disable",
			run:  runObservability,
			args: []string{"disable", "--config", configPath, "--env", "prod"},
		},
		{
			name: "rollback host",
			run:  runRollback,
			args: []string{"host", "--config", configPath, "--env", "prod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run(tt.args, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil {
				t.Fatal("expected missing overlay error")
			}
			if got := err.Error(); !strings.Contains(got, `environment overlay "prod" not found`) {
				t.Fatalf("unexpected error %q", got)
			}
		})
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
	err := runRollback([]string{"host", "--config", configPath, "--env", "prod"}, &bytes.Buffer{}, &errOut)
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
