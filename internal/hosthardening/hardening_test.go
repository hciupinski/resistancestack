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
		"absent_root=\"${op_dir}/absent\"",
		"sudo touch \"${absent_marker}\"",
		"snapshot_service_states",
		"snapshot_ufw_state",
		"ufw-status-numbered.txt",
		"ufw-show-added.txt",
		"backup_tree /etc/ufw",
		"printf 'tool_version=%s\\n' \"${TOOL_VERSION}\"",
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
	if !strings.Contains(script, "sudo find /etc/sudoers.d -maxdepth 1 -type f -name 'resistack-*' -exec rm -f {} +") {
		t.Fatal("expected rollback script to remove ResistanceStack-managed sudoers snippets")
	}
	for _, expected := range []string{
		"DRY_RUN='false'",
		"operation manifest",
		"restore_path",
		"remove file created by host-hardening",
		"sudo test -f \"${latest}/manifest.txt\"",
		"done < <(sudo cat \"${latest}/manifest.txt\")",
		"previous ufw numbered status",
		"previous ufw added rules",
		"restart affected service: fail2ban",
		"restart affected service: ssh",
		"restore ufw service state and reload firewall",
		"no host-hardening backup is available",
		"manual recovery: inspect /etc/ssh/sshd_config",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in rollback script", expected)
		}
	}
}

func TestBuildRollbackScript_DryRunDoesNotChangeHost(t *testing.T) {
	cfg := config.Default("demo")
	script := BuildRollbackScriptWithOptions(cfg, true)

	for _, expected := range []string{
		"DRY_RUN='true'",
		"dry-run complete; no host changes were made",
		"[ \"${DRY_RUN}\" = \"true\" ] && return 0",
		"[ \"${DRY_RUN}\" = \"true\" ] || sudo systemctl restart fail2ban",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected %q in rollback dry-run script", expected)
		}
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
