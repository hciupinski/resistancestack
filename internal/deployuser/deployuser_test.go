package deployuser

import (
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
}

func TestResolveOptions_RejectsWhitespaceUser(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.PrivateKeyPath = writePublicKeyPair(t)

	_, err := ResolveOptions(cfg, Options{User: "bad user"})
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
		"sudo -n -u \"${DEPLOY_USER}\" sudo -n true",
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
		"sudo -n -u \"${DEPLOY_USER}\" sudo -n true",
		"deploy user bootstrap complete",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in bootstrap script", expected)
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
