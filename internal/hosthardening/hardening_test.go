package hosthardening

import (
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestBuildApplyScript_ContainsGuardrailsAndBackups(t *testing.T) {
	cfg := config.Default("demo")
	script := BuildApplyScript(cfg)

	for _, expected := range []string{
		"require_privileged_access",
		"passwordless sudo is required for host hardening",
		"validate_current_operator",
		"backup_file /etc/ssh/sshd_config",
		"sudo sshd -t",
		"sudo ufw default",
		"/etc/fail2ban/jail.d/resistack-sshd.local",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in script", expected)
		}
	}
}

func TestBuildRollbackScript_RestoresLastBackup(t *testing.T) {
	cfg := config.Default("demo")
	script := BuildRollbackScript(cfg)
	if !strings.Contains(script, `readlink -f "${BACKUP_ROOT}/last"`) {
		t.Fatal("expected last-backup lookup")
	}
	if !strings.Contains(script, "manifest.txt") {
		t.Fatal("expected manifest use")
	}
}
