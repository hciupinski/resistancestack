package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInitUpdatesExistingConfigWithMissingDefaults(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "resistack.yaml")
	raw := `project_name: demo
mode:
  strategy: audit_then_apply
server:
  host: 1.2.3.4
  ssh_user: custom-user
  ssh_port: 22
  private_key_path: ~/.ssh/id_ed25519
  host_key_checking: strict
  known_hosts_path: ~/.ssh/known_hosts
host_hardening:
  enabled: true
  ssh_hardening:
    disable_root_login: true
    disable_password_auth: true
    max_auth_tries: 4
    login_grace_time_seconds: 30
    guard_current_operator: true
    require_passwordless_sudo: true
  ufw_policy:
    enabled: true
    default_incoming: deny
    default_outgoing: allow
    allowed_tcp_ports: [22, 80, 443]
    admin_allowlist: ["203.0.113.10/32"]
  fail2ban:
    enabled: true
    ban_time: 1h
    find_time: 10m
    max_retry: 5
    recidive_enabled: true
    recidive_ban_time: 24h
  automatic_security_updates: true
  check_deploy_user: true
  check_docker_daemon: true
  backup_dir: /var/lib/resistack/backups/host
`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out bytes.Buffer
	if err := Run([]string{"init", "--config", configPath, "demo"}, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("run init: %v", err)
	}

	message := out.String()
	if !strings.Contains(message, "Updated "+configPath+" with ") {
		t.Fatalf("expected update message, got %q", message)
	}
	if !strings.Contains(message, "host_hardening.ufw_policy.operator_access_mode") {
		t.Fatalf("expected added key list in message, got %q", message)
	}
	if !strings.Contains(message, "host_hardening.ssl_certificates") {
		t.Fatalf("expected ssl_certificates block in added key list, got %q", message)
	}

	updated, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read updated config: %v", err)
	}
	updatedRaw := string(updated)
	if !strings.Contains(updatedRaw, "ssh_user: custom-user") {
		t.Fatal("expected existing values to be preserved")
	}
	if !strings.Contains(updatedRaw, "operator_access_mode: public_hardened # SSH operator access strategy. Options: public_hardened, allowlist_only.") {
		t.Fatal("expected missing operator access mode to be added with inline comment")
	}
	if !strings.Contains(updatedRaw, "preserve_current_session: true # Temporarily preserve the current SSH session when needed.") {
		t.Fatal("expected missing preserve_current_session to be added with inline comment")
	}
	if !strings.Contains(updatedRaw, "auto_issue: false # Automatically issue a missing or expired Let's Encrypt certificate during host hardening.") {
		t.Fatal("expected missing ssl_certificates.auto_issue to be added with inline comment")
	}
}

func TestRunInitReportsWhenConfigAlreadyUpToDate(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "resistack.yaml")

	var first bytes.Buffer
	if err := Run([]string{"init", "--config", configPath, "demo"}, &first, &bytes.Buffer{}); err != nil {
		t.Fatalf("first init: %v", err)
	}

	var second bytes.Buffer
	if err := Run([]string{"init", "--config", configPath, "demo"}, &second, &bytes.Buffer{}); err != nil {
		t.Fatalf("second init: %v", err)
	}

	if got := second.String(); !strings.Contains(got, configPath+" is already up to date") {
		t.Fatalf("expected already-up-to-date message, got %q", got)
	}
}
