package deployuser

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestResolveOptions_UsesPreferredDeployUserAndConfiguredPublicKey(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.SSHUser = "root"
	cfg.HostHardening.SSHHardening.AllowUsers = []string{"deployer"}

	keyDir := t.TempDir()
	privateKeyPath := filepath.Join(keyDir, "id_ed25519")
	publicKeyPath := privateKeyPath + ".pub"
	if err := os.WriteFile(privateKeyPath, []byte("private"), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	wantKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest deployer@example"
	if err := os.WriteFile(publicKeyPath, []byte(wantKey+"\n"), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	cfg.Server.PrivateKeyPath = privateKeyPath

	opts, err := ResolveOptions(cfg, Options{})
	if err != nil {
		t.Fatalf("ResolveOptions() error = %v", err)
	}
	if opts.User != "deployer" {
		t.Fatalf("ResolveOptions().User = %q, want deployer", opts.User)
	}
	if opts.ConnectAs != "root" {
		t.Fatalf("ResolveOptions().ConnectAs = %q, want root", opts.ConnectAs)
	}
	if opts.PublicKeyPath != publicKeyPath {
		t.Fatalf("ResolveOptions().PublicKeyPath = %q, want %q", opts.PublicKeyPath, publicKeyPath)
	}
	if opts.PublicKey != wantKey {
		t.Fatalf("ResolveOptions().PublicKey = %q, want %q", opts.PublicKey, wantKey)
	}
	if opts.SudoMode != config.SudoModeLimited {
		t.Fatalf("ResolveOptions().SudoMode = %q, want limited", opts.SudoMode)
	}
}

func TestResolveOptions_RejectsWhitespaceUser(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.PrivateKeyPath = writePublicKeyPair(t)

	_, err := ResolveOptions(cfg, Options{User: "bad user"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveOptions_RejectsSudoersSyntaxUser(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.PrivateKeyPath = writePublicKeyPair(t)

	_, err := ResolveOptions(cfg, Options{User: "deployer,root"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildCheckScript_ValidatesExpectedKeyAndSudo(t *testing.T) {
	script := BuildCheckScript(Options{
		User:      "deployer",
		PublicKey: "ssh-ed25519 AAAA test@example",
	})

	for _, expected := range []string{
		"checking deploy user ${DEPLOY_USER}",
		"authorized_keys present",
		"expected public key is installed",
		"passwordless sudo is enabled",
		"sudo -n -u \"${DEPLOY_USER}\" sudo -n -l",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in check script", expected)
		}
	}
}

func TestBuildBootstrapScript_IsIdempotent(t *testing.T) {
	script := BuildBootstrapScript(Options{
		User:      "deployer",
		PublicKey: "ssh-ed25519 AAAA test@example",
	})

	for _, expected := range []string{
		"useradd --create-home --shell /bin/bash",
		"primary_group_for_user()",
		"primary_group=\"$(primary_group_for_user \"${DEPLOY_USER}\")\"",
		"install -d -m 0700 -o \"${DEPLOY_USER}\" -g \"${primary_group}\"",
		"public key already installed",
		"passwordless sudo already configured",
		"SUDO_MODE='limited'",
		"Cmnd_Alias RESISTACK_DEPLOY",
		"sudo visudo -cf \"${tmp}\"",
		"sudo install -m 0440 \"${tmp}\" \"${sudoers_path}\"",
		"sudo -n -u \"${DEPLOY_USER}\" sudo -n -l",
		"deploy user bootstrap complete",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in bootstrap script", expected)
		}
	}
}

func TestBuildBootstrapScript_ManualModePrintsInstructionsWithoutInstallingSudoers(t *testing.T) {
	script := BuildBootstrapScript(Options{
		User:      "deployer",
		PublicKey: "ssh-ed25519 AAAA test@example",
		SudoMode:  config.SudoModeManual,
	})

	for _, expected := range []string{
		"SUDO_MODE='manual'",
		"sudo_mode=manual; not modifying ${sudoers_path}",
		"suggested sudoers content",
		"skipping passwordless sudo verification because sudo_mode=manual",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in bootstrap script", expected)
		}
	}
}

func TestBuildBootstrapScript_FullModeContainsNOPASSWDAll(t *testing.T) {
	script := BuildBootstrapScript(Options{
		User:      "deployer",
		PublicKey: "ssh-ed25519 AAAA test@example",
		SudoMode:  config.SudoModeFull,
	})

	if !strings.Contains(script, "deployer ALL=(ALL) NOPASSWD:ALL") {
		t.Fatal("expected full sudoers rule")
	}
	if strings.Contains(script, "Cmnd_Alias RESISTACK_DEPLOY") {
		t.Fatal("expected full mode not to use limited sudo alias")
	}
}

func TestBootstrap_FullModeRequiresExplicitRiskAcceptance(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.PrivateKeyPath = writePublicKeyPair(t)
	cfg.HostHardening.SudoMode = config.SudoModeFull

	err := Bootstrap(cfg, Options{}, true, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected risk acceptance error")
	}
	if !strings.Contains(err.Error(), "--accept-sudo-all-risk") {
		t.Fatalf("unexpected error %q", err.Error())
	}
}

func TestBootstrap_DryRunPrintsRiskReport(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.PrivateKeyPath = writePublicKeyPair(t)

	var out bytes.Buffer
	if err := Bootstrap(cfg, Options{}, true, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("bootstrap dry-run: %v", err)
	}
	got := out.String()
	for _, expected := range []string{
		"Deploy user sudo risk profile: limited",
		"sudo mode: limited",
		"Generated deploy-user bootstrap script:",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("expected %q in dry-run output, got %q", expected, got)
		}
	}
}

func writePublicKeyPair(t *testing.T) string {
	t.Helper()
	keyDir := t.TempDir()
	privateKeyPath := filepath.Join(keyDir, "id_ed25519")
	publicKeyPath := privateKeyPath + ".pub"
	if err := os.WriteFile(privateKeyPath, []byte("private"), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(publicKeyPath, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest deployer@example\n"), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return privateKeyPath
}
