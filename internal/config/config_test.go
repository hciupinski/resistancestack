package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_NewV2Config(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "resistack.yaml")
	raw := `project_name: demo
mode:
  strategy: audit_then_apply
server:
  host: 1.2.3.4
  ssh_user: deployer
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
    operator_access_mode: public_hardened
    preserve_current_session: true
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
app_inventory:
  compose_paths: [docker-compose.yml]
  nginx_paths: [/etc/nginx/sites-enabled]
  systemd_units: [nginx]
  domains: [app.example.com]
  healthcheck_urls: [http://127.0.0.1:8080/health]
observability:
  enable: true
  log_sources: [journald, nginx, docker, fail2ban]
  host_metrics: true
  panel_bind: 127.0.0.1:9400
  local_data_dir: /var/lib/resistack/observability
ci:
  provider: github_actions
  generate_workflows: true
  mode: warn-only
  schedule: "24 3 * * *"
  scans:
    dependency: true
    image: true
    sbom: true
    secrets: true
    license: true
    osv: true
reporting:
  output_path: ./.resistack/reports
  format: text
  minimum_severity: low
alerts:
  enabled: true
  webhook_url: https://hooks.example.com/security
  email: security@example.com
  slack_url: https://hooks.slack.com/services/T000/B000/XXX
  thresholds:
    ssh_failures_15m: 25
    bans_15m: 10
    nginx_errors_15m: 30
    container_restarts: 3
    disk_percent_used: 85
    cert_expiry_days: 21
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Mode.Strategy != ModeAuditThenApply {
		t.Fatalf("unexpected mode: %s", cfg.Mode.Strategy)
	}
	if cfg.CI.Provider != CIProviderGitHub {
		t.Fatalf("unexpected ci provider: %s", cfg.CI.Provider)
	}
	if cfg.HostHardening.BackupDir == "" {
		t.Fatal("expected host hardening backup dir")
	}
	if cfg.HostHardening.UFWPolicy.OperatorAccessMode != OperatorAccessModePublicHardened {
		t.Fatalf("unexpected operator access mode: %s", cfg.HostHardening.UFWPolicy.OperatorAccessMode)
	}
	if !cfg.HostHardening.UFWPolicy.PreserveCurrentSession {
		t.Fatal("expected preserve_current_session=true")
	}
}

func TestEnsureDefaultConfigCreatesCommentedConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "resistack.yaml")

	result, err := EnsureDefaultConfig(path, "demo", false)
	if err != nil {
		t.Fatalf("ensure default config: %v", err)
	}
	if !result.Created {
		t.Fatal("expected config to be created")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "strategy: audit_then_apply # Workflow mode. Options: audit_then_apply.") {
		t.Fatal("expected inline comment for mode.strategy")
	}
	if !strings.Contains(text, "operator_access_mode: public_hardened # SSH operator access strategy. Options: public_hardened, allowlist_only.") {
		t.Fatal("expected inline comment for operator_access_mode")
	}
	if !strings.Contains(text, "sarif_upload_mode: auto # SARIF upload strategy. Options: auto, enabled, disabled.") {
		t.Fatal("expected inline comment for ci.github.sarif_upload_mode")
	}
	if !strings.Contains(text, "- 22 # TCP port kept reachable on the host.") {
		t.Fatal("expected inline comment for allowed_tcp_ports entries")
	}
}

func TestEnsureDefaultConfigMergesMissingKeysWithoutOverwritingExistingValues(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "resistack.yaml")
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
    admin_allowlist: []
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
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := EnsureDefaultConfig(path, "demo", false)
	if err != nil {
		t.Fatalf("ensure default config: %v", err)
	}
	if len(result.Added) == 0 {
		t.Fatal("expected missing keys to be added")
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Server.SSHUser != "custom-user" {
		t.Fatalf("expected existing ssh user to be preserved, got %q", cfg.Server.SSHUser)
	}
	if cfg.HostHardening.UFWPolicy.OperatorAccessMode != OperatorAccessModePublicHardened {
		t.Fatalf("expected operator_access_mode to be merged, got %q", cfg.HostHardening.UFWPolicy.OperatorAccessMode)
	}
	if !cfg.HostHardening.UFWPolicy.PreserveCurrentSession {
		t.Fatal("expected preserve_current_session to be merged")
	}

	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read updated config: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, "ssh_user: custom-user") {
		t.Fatal("expected existing ssh user value to remain unchanged")
	}
	if !strings.Contains(text, "operator_access_mode: public_hardened # SSH operator access strategy. Options: public_hardened, allowlist_only.") {
		t.Fatal("expected merged key to include inline comment")
	}
	if !strings.Contains(text, "sarif_upload_mode: auto # SARIF upload strategy. Options: auto, enabled, disabled.") {
		t.Fatal("expected merged github SARIF config to include inline comment")
	}
}
