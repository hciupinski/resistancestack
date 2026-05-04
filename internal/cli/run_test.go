package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestRun_PrintsUsageWhenNoArgs(t *testing.T) {
	var out bytes.Buffer

	if err := Run(nil, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if got := out.String(); !strings.Contains(got, "ResistanceStack v2 CLI") || !strings.Contains(got, "Available Commands:") {
		t.Fatalf("expected usage output, got %q", got)
	}
}

func TestRun_PrintsUsageForHelpAliases(t *testing.T) {
	aliases := [][]string{{"help"}, {"-h"}, {"--help"}}

	for _, args := range aliases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out bytes.Buffer
			if err := Run(args, &out, &bytes.Buffer{}); err != nil {
				t.Fatalf("run %v: %v", args, err)
			}
			if got := out.String(); !strings.Contains(got, "Commands:") {
				t.Fatalf("expected command list, got %q", got)
			}
		})
	}
}

func TestRun_ReturnsUnknownCommandError(t *testing.T) {
	err := Run([]string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected unknown command error")
	}
	if got := err.Error(); !strings.Contains(got, `unknown command "unknown"`) {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestRun_CIRequiresSubcommand(t *testing.T) {
	err := Run([]string{"ci"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected missing ci subcommand error")
	}
	if got := err.Error(); got != "ci requires a subcommand: generate or validate" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestRun_ObservabilityRequiresSubcommand(t *testing.T) {
	err := Run([]string{"observability"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected missing observability subcommand error")
	}
	if got := err.Error(); got != "observability requires a subcommand: enable or disable" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestRun_DeployUserRequiresSubcommand(t *testing.T) {
	err := Run([]string{"deploy-user"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected missing deploy-user subcommand error")
	}
	if got := err.Error(); got != "deploy-user requires a subcommand: check or bootstrap" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestRun_RootHelpShowsPersistentFlagsAndCompletion(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"--help"}, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("run help: %v", err)
	}
	got := out.String()
	for _, want := range []string{"--config", "--env", "--output", "--verbose", "--non-interactive", "completion"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected help to contain %q, got %q", want, got)
		}
	}
}

func TestRun_CommandHelpShowsPersistentFlags(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"audit", "--help"}, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("run audit help: %v", err)
	}
	got := out.String()
	for _, want := range []string{"--dry-run", "--config", "--env", "--output"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected audit help to contain %q, got %q", want, got)
		}
	}
}

func TestRun_InventoryLocalWorksWithoutConfigOrSSHKey(t *testing.T) {
	root := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get wd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	if err := Run([]string{"inventory", "--local"}, &out, &errOut); err != nil {
		t.Fatalf("inventory --local: %v; stderr=%s", err, errOut.String())
	}

	got := out.String()
	for _, want := range []string{"Areas: repo=checked host=not_checked cloud/external=not_checked", "Host not checked:", "Runtime: unknown"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected local inventory output to contain %q, got %q", want, got)
		}
	}
}

func TestRun_AuditLocalWritesReportWithNotCheckedFindings(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatalf("mkdir workflows: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "workflows", "deploy.yml"), []byte("name: deploy\n"), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get wd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	if err := Run([]string{"audit", "--local"}, &out, &errOut); err != nil {
		t.Fatalf("audit --local: %v; stderr=%s", err, errOut.String())
	}

	got := out.String()
	for _, want := range []string{"not_checked: 2", "Host hardening checks were not executed.", "Existing GitHub Actions workflows were found"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected local audit output to contain %q, got %q", want, got)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".resistack", "reports", "audit-report.txt")); err != nil {
		t.Fatalf("expected audit report to be written: %v", err)
	}
}

func TestRun_DoctorLocalWritesReportAndReturnsFailures(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "resistack.yaml")
	cfg := config.Default("demo")
	cfg.Server.PrivateKeyPath = filepath.Join(root, "missing-key")
	cfg.Server.HostKeyChecking = "accept-new"
	cfg.Reporting.OutputPath = filepath.Join(root, "reports")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var out bytes.Buffer
	err := Run([]string{"doctor", "--local", "--config", configPath}, &out, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected doctor to return failing status")
	}
	if got := ExitCode(err); got != 1 {
		t.Fatalf("unexpected exit code %d", got)
	}
	got := out.String()
	for _, want := range []string{"Status: fail", "Configured private key exists locally.", "Saved doctor report to"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected doctor output to contain %q, got %q", want, got)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "reports", "doctor-report.txt")); err != nil {
		t.Fatalf("expected doctor report to be written: %v", err)
	}
}
