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
		"verify_future_ssh_access",
		"require_ssh_login_candidate",
		"refusing to disable root login without an explicit non-root allow_users entry",
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

func TestBuildApplyScript_RestartsSSHWithFallbacks(t *testing.T) {
	cfg := config.Default("demo")
	script := BuildApplyScript(cfg)

	for _, expected := range []string{
		"restart_ssh_service()",
		"sudo systemctl restart ssh >/dev/null 2>&1",
		"sudo systemctl restart sshd >/dev/null 2>&1",
		"sudo service ssh restart >/dev/null 2>&1",
		"sudo service sshd restart >/dev/null 2>&1",
		"restart_ssh_service",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in script", expected)
		}
	}
	if strings.Contains(script, "if systemctl list-unit-files | grep -q '^ssh.service'; then") {
		t.Fatal("expected brittle SSH unit detection to be removed")
	}
}

func TestBuildApplyScript_GuardsManagedAllowUsersWithCurrentOperator(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.SSHUser = "root"
	cfg.HostHardening.SSHHardening.AllowUsers = []string{"deployer"}

	script := BuildApplyScript(cfg)

	if !strings.Contains(script, "ALLOW_USERS='deployer root'") {
		t.Fatal("expected guarded AllowUsers list to preserve current operator")
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
	if !strings.Contains(script, "restart_ssh_service()") {
		t.Fatal("expected rollback script to reuse SSH restart fallback helper")
	}
}

func TestBuildApplyScript_IncludesManagedSSLCertWorkflow(t *testing.T) {
	cfg := config.Default("demo")
	cfg.HostHardening.SSLCertificates.AutoIssue = true
	script := BuildApplyScript(cfg)

	for _, expected := range []string{
		"SSL_CERTIFICATES_ENABLED='true'",
		"SSL_CERTIFICATES_AUTO_ISSUE='true'",
		"SSL_PRIMARY_DOMAIN='app.example.com'",
		"sudo apt-get install -y ufw fail2ban certbot",
		"find_certbot_managed_certificate_lineage()",
		"find_matching_certificate_path()",
		"sudo python3 - \"$1\" <<'PY'",
		"[\"certbot\", \"certificates\"]",
		"validate_certbot_managed_lineage()",
		"certificate_is_valid()",
		"sudo openssl x509 -in \"${fullchain}\" -noout -checkend 0 >/dev/null 2>&1",
		"stop_known_proxy_for_certbot()",
		"selected certbot-managed lineage for ${SSL_PRIMARY_DOMAIN}",
		"selected certificate lineage for post-issue verification",
		"certbot finished, but no managed certificate lineage matched ${SSL_PRIMARY_DOMAIN} in local certbot inventory",
		"sudo certbot \"${certbot_args[@]}\"",
		"certbot_args+=(--cert-name \"${cert_name}\" --force-renewal)",
		"ensure_managed_certificate",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in script", expected)
		}
	}
}
