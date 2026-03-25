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
		"parse_current_operator_ip",
		"cleanup_bootstrap_rules",
		"resistack-bootstrap",
		"backup_file /etc/ssh/sshd_config",
		"sudo sshd -t",
		"operator access mode",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in script", expected)
		}
	}
}

func TestBuildApplyScript_CleansBootstrapRulesWithoutBrokenPythonPipe(t *testing.T) {
	cfg := config.Default("demo")
	script := BuildApplyScript(cfg)

	if !strings.Contains(script, `status_output="$(sudo ufw status numbered 2>/dev/null || true)"`) {
		t.Fatal("expected ufw status capture to tolerate inactive firewall state")
	}
	if !strings.Contains(script, `printf '%s\n' "${status_output}" | python3 -c '`) {
		t.Fatal("expected bootstrap cleanup parser to read ufw status from stdin via python -c")
	}
	if strings.Contains(script, `sudo ufw status numbered 2>/dev/null | python3 - <<'PY'`) {
		t.Fatal("expected broken python heredoc pipeline to be removed")
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
