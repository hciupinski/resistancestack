package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestRunWizardCreatesCommentedConfigFromAnswers(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "resistack.yaml")
	input := strings.Join([]string{
		"demo",
		"vps.example.com",
		"deployer",
		"2222",
		"~/.ssh/resistack",
		"accept-new",
		"app.example.com, api.example.com",
		"https://app.example.com/health",
		"deployer",
		"198.51.100.10/32",
		"ops@example.com",
		"y",
		"n",
		"y",
		"",
	}, "\n")

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := NewRootCommand(&out, &errOut)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs([]string{"wizard", "--config", configPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("wizard: %v; stdout=%s stderr=%s", err, out.String(), errOut.String())
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load generated config: %v", err)
	}
	if cfg.ProjectName != "demo" {
		t.Fatalf("unexpected project name %q", cfg.ProjectName)
	}
	if cfg.Server.Host != "vps.example.com" || cfg.Server.SSHUser != "deployer" || cfg.Server.SSHPort != 2222 {
		t.Fatalf("unexpected server config: %#v", cfg.Server)
	}
	if cfg.Server.HostKeyChecking != "accept-new" {
		t.Fatalf("unexpected host key checking %q", cfg.Server.HostKeyChecking)
	}
	if got := cfg.AppInventory.Domains; len(got) != 2 || got[0] != "app.example.com" || got[1] != "api.example.com" {
		t.Fatalf("unexpected domains %#v", got)
	}
	if got := cfg.HostHardening.SSHHardening.AllowUsers; len(got) != 1 || got[0] != "deployer" {
		t.Fatalf("unexpected allow users %#v", got)
	}
	if !cfg.HostHardening.SSLCertificates.AutoIssue {
		t.Fatal("expected auto_issue=true")
	}
	if cfg.Observability.Enable {
		t.Fatal("expected observability disabled")
	}
	if !cfg.CI.GenerateWorkflows {
		t.Fatal("expected CI workflows enabled")
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "server:") || !strings.Contains(text, "host: vps.example.com # Target VPS hostname or IP.") {
		t.Fatalf("expected generated config to include comments, got %s", text)
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected no stderr, got %q", errOut.String())
	}
	if !strings.Contains(out.String(), "Created "+configPath) {
		t.Fatalf("expected created message, got %q", out.String())
	}
}

func TestRunWizardDoesNotOverwriteExistingConfigWithoutForce(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "resistack.yaml")
	if err := os.WriteFile(configPath, []byte("project_name: existing\n"), 0o600); err != nil {
		t.Fatalf("write existing config: %v", err)
	}

	cmd := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"wizard", "--config", configPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected existing config error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected error %q", err.Error())
	}
}

func TestRunWizardRejectsNonInteractiveMode(t *testing.T) {
	err := Run([]string{"wizard", "--non-interactive"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected non-interactive wizard error")
	}
	if !strings.Contains(err.Error(), "requires interactive input") {
		t.Fatalf("unexpected error %q", err.Error())
	}
}
