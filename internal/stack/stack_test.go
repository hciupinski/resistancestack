package stack

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/hosthardening"
)

func TestParseModules_DefaultsToAll(t *testing.T) {
	modules, err := parseModules(nil)
	if err != nil {
		t.Fatalf("parse modules: %v", err)
	}
	if len(modules) != 4 {
		t.Fatalf("expected 4 modules, got %d", len(modules))
	}
}

func TestApplyDryRun_PrintsHostHardeningScript(t *testing.T) {
	cfg := config.Default("demo")
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg.Server.PrivateKeyPath = keyPath
	cfg.Server.HostKeyChecking = "accept-new"
	var out bytes.Buffer

	err := Apply(cfg, t.TempDir(), []string{string(ModuleHostHardening)}, true, &out, &out)
	if err != nil {
		t.Fatalf("apply dry-run: %v", err)
	}
	if !strings.Contains(out.String(), "Host hardening access preview:") {
		t.Fatal("expected access preview in dry-run output")
	}
	if !strings.Contains(out.String(), "backup_file /etc/ssh/sshd_config") {
		t.Fatal("expected backup logic in dry-run output")
	}
	if !strings.Contains(out.String(), "sudo ufw") {
		t.Fatal("expected ufw commands in dry-run output")
	}
}

func TestRollbackHostScriptRestoresManifest(t *testing.T) {
	cfg := config.Default("demo")
	script := hosthardening.BuildRollbackScript(cfg)
	if !strings.Contains(script, "manifest.txt") {
		t.Fatal("expected rollback manifest restore")
	}
	if !strings.Contains(script, "sudo cp -a") {
		t.Fatal("expected file restore command")
	}
}
