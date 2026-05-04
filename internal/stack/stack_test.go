package stack

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/doctor"
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

	err := Apply(cfg, t.TempDir(), []string{string(ModuleHostHardening)}, true, false, &out, &out)
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

func TestApplyHostHardeningRequiresPassingDoctor(t *testing.T) {
	cfg := config.Default("demo")
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg.Server.PrivateKeyPath = keyPath
	cfg.Server.HostKeyChecking = "accept-new"

	originalRunDoctor := runDoctor
	runDoctor = func(config.Config, string, doctor.Options) (doctor.Report, error) {
		return doctor.Report{
			GeneratedAt: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
			Mode:        doctor.ModeAll,
			Status:      doctor.StatusFail,
			Checks: []doctor.Check{{
				Area:          doctor.ModeRemote,
				ID:            "remote.systemd",
				Status:        doctor.StatusFail,
				Description:   "systemd is available and running on the remote host.",
				DetectedValue: "systemd_running=false",
			}},
		}, nil
	}
	t.Cleanup(func() {
		runDoctor = originalRunDoctor
	})

	var out bytes.Buffer
	err := Apply(cfg, t.TempDir(), []string{string(ModuleHostHardening)}, false, false, &out, &out)
	if err == nil {
		t.Fatal("expected doctor failure")
	}
	if got := err.Error(); !strings.Contains(got, "doctor checks failed") {
		t.Fatalf("unexpected error %q", got)
	}
	if got := out.String(); !strings.Contains(got, "remote.systemd") && !strings.Contains(got, "systemd is available") {
		t.Fatalf("expected doctor report in output, got %q", got)
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
