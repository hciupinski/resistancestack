package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestCheckLocal_ReportsMissingSSHKeyAndWritableOutputPath(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default("demo")
	cfg.Server.PrivateKeyPath = filepath.Join(root, "missing-key")
	cfg.Server.HostKeyChecking = "accept-new"
	cfg.Reporting.OutputPath = "reports"

	checks := CheckLocal(cfg, root, "test-version")

	assertCheck(t, checks, "local.binary.version", StatusPass)
	assertCheck(t, checks, "local.ssh.private_key", StatusFail)
	assertCheck(t, checks, "local.ssh.known_hosts", StatusWarn)
	assertCheck(t, checks, "local.reporting.output_path", StatusPass)
	if _, err := os.Stat(filepath.Join(root, "reports")); err != nil {
		t.Fatalf("expected output path to be created: %v", err)
	}
}

func TestFormatText_RendersRecommendations(t *testing.T) {
	report := Report{
		GeneratedAt: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
		Mode:        ModeLocal,
		Status:      StatusFail,
		Checks: []Check{{
			Area:           ModeLocal,
			ID:             "local.ssh.private_key",
			Status:         StatusFail,
			Description:    "Configured private key exists locally.",
			DetectedValue:  "missing",
			Recommendation: "Set `server.private_key_path`.",
		}},
	}

	got := FormatText(report)
	for _, want := range []string{"Doctor generated at: 2026-05-04T12:00:00Z", "Status: fail", "[FAIL] Configured private key exists locally.", "recommendation: Set `server.private_key_path`."} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected text report to contain %q, got %q", want, got)
		}
	}
}

func TestRemoteChecks_ClassifiesRequiredAndOptionalTools(t *testing.T) {
	cfg := config.Default("demo")
	payload := remotePayload{
		OS:             "Ubuntu 24.04",
		Bash:           true,
		Python3:        true,
		Sudo:           true,
		Systemctl:      true,
		SystemdRunning: true,
		AptGet:         true,
		SSHD:           true,
		UFW:            false,
		Fail2ban:       false,
		Certbot:        false,
		Docker:         false,
	}

	checks := remoteChecksFromPayload(cfg, payload)

	assertCheck(t, checks, "remote.systemd", StatusPass)
	assertCheck(t, checks, "remote.ufw", StatusWarn)
	assertCheck(t, checks, "remote.fail2ban", StatusWarn)
	assertCheck(t, checks, "remote.docker", StatusWarn)
	assertCheck(t, checks, "remote.certbot", StatusWarn)
}

func TestRemoteChecks_CertbotFailsWhenAutoIssueEnabled(t *testing.T) {
	cfg := config.Default("demo")
	cfg.HostHardening.SSLCertificates.AutoIssue = true
	payload := remotePayload{
		OS:             "Ubuntu 24.04",
		Bash:           true,
		Python3:        true,
		Sudo:           true,
		Systemctl:      true,
		SystemdRunning: true,
		AptGet:         true,
		SSHD:           true,
	}

	checks := remoteChecksFromPayload(cfg, payload)

	assertCheck(t, checks, "remote.certbot", StatusFail)
}

func assertCheck(t *testing.T, checks []Check, id string, status string) {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			if check.Status != status {
				t.Fatalf("check %s status = %s, want %s", id, check.Status, status)
			}
			return
		}
	}
	t.Fatalf("missing check %s", id)
}
