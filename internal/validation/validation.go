package validation

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
)

var severityRank = map[string]int{
	config.SeverityLow:      1,
	config.SeverityMedium:   2,
	config.SeverityHigh:     3,
	config.SeverityCritical: 4,
}

func Check(cfg config.Config) (warnings []string, errs []error) {
	if strings.TrimSpace(cfg.ProjectName) == "" {
		errs = append(errs, fmt.Errorf("project_name is required"))
	}

	if strings.TrimSpace(cfg.Mode.Strategy) == "" {
		errs = append(errs, fmt.Errorf("mode.strategy is required"))
	} else if cfg.Mode.Strategy != config.ModeAuditThenApply {
		errs = append(errs, fmt.Errorf("mode.strategy must be %q", config.ModeAuditThenApply))
	}

	if strings.TrimSpace(cfg.Server.Host) == "" {
		errs = append(errs, fmt.Errorf("server.host is required"))
	}
	if strings.TrimSpace(cfg.Server.SSHUser) == "" {
		errs = append(errs, fmt.Errorf("server.ssh_user is required"))
	}
	if cfg.Server.SSHPort <= 0 || cfg.Server.SSHPort > 65535 {
		errs = append(errs, fmt.Errorf("server.ssh_port must be between 1 and 65535"))
	}
	if strings.TrimSpace(cfg.Server.PrivateKeyPath) == "" {
		errs = append(errs, fmt.Errorf("server.private_key_path is required"))
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Server.HostKeyChecking)) {
	case "", "strict", "accept-new":
	default:
		errs = append(errs, fmt.Errorf("server.host_key_checking must be one of: strict, accept-new"))
	}
	if strings.EqualFold(strings.TrimSpace(cfg.Server.HostKeyChecking), "strict") && strings.TrimSpace(cfg.Server.KnownHostsPath) == "" {
		errs = append(errs, fmt.Errorf("server.known_hosts_path is required when server.host_key_checking=strict"))
	}

	if !cfg.HostHardening.Enabled {
		warnings = append(warnings, "host_hardening.enabled=false; baseline hardening will not be applied")
	}
	if cfg.HostHardening.SSHHardening.MaxAuthTries <= 0 {
		errs = append(errs, fmt.Errorf("host_hardening.ssh_hardening.max_auth_tries must be > 0"))
	}
	if cfg.HostHardening.SSHHardening.LoginGraceTimeSeconds <= 0 {
		errs = append(errs, fmt.Errorf("host_hardening.ssh_hardening.login_grace_time_seconds must be > 0"))
	}
	if cfg.HostHardening.UFWPolicy.Enabled {
		switch strings.ToLower(strings.TrimSpace(cfg.HostHardening.UFWPolicy.DefaultIncoming)) {
		case "allow", "deny", "reject":
		default:
			errs = append(errs, fmt.Errorf("host_hardening.ufw_policy.default_incoming must be one of: allow, deny, reject"))
		}
		switch strings.ToLower(strings.TrimSpace(cfg.HostHardening.UFWPolicy.DefaultOutgoing)) {
		case "allow", "deny", "reject":
		default:
			errs = append(errs, fmt.Errorf("host_hardening.ufw_policy.default_outgoing must be one of: allow, deny, reject"))
		}
		if len(cfg.HostHardening.UFWPolicy.AllowedTCPPorts) == 0 {
			warnings = append(warnings, "host_hardening.ufw_policy.allowed_tcp_ports is empty; only admin allowlist may preserve SSH access")
		}
	}
	for _, entry := range cfg.HostHardening.UFWPolicy.AdminAllowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, err := netip.ParsePrefix(entry); err != nil {
			errs = append(errs, fmt.Errorf("host_hardening.ufw_policy.admin_allowlist contains invalid CIDR %q", entry))
		}
	}
	if strings.TrimSpace(cfg.HostHardening.BackupDir) == "" {
		errs = append(errs, fmt.Errorf("host_hardening.backup_dir is required"))
	}
	if cfg.HostHardening.Fail2ban.Enabled {
		if strings.TrimSpace(cfg.HostHardening.Fail2ban.BanTime) == "" {
			errs = append(errs, fmt.Errorf("host_hardening.fail2ban.ban_time is required"))
		}
		if strings.TrimSpace(cfg.HostHardening.Fail2ban.FindTime) == "" {
			errs = append(errs, fmt.Errorf("host_hardening.fail2ban.find_time is required"))
		}
		if cfg.HostHardening.Fail2ban.MaxRetry <= 0 {
			errs = append(errs, fmt.Errorf("host_hardening.fail2ban.max_retry must be > 0"))
		}
		if cfg.HostHardening.Fail2ban.RecidiveEnabled && strings.TrimSpace(cfg.HostHardening.Fail2ban.RecidiveBanTime) == "" {
			errs = append(errs, fmt.Errorf("host_hardening.fail2ban.recidive_ban_time is required when recidive_enabled=true"))
		}
	}

	switch strings.ToLower(strings.TrimSpace(cfg.CI.Provider)) {
	case config.CIProviderGitHub:
	default:
		errs = append(errs, fmt.Errorf("ci.provider must be %q", config.CIProviderGitHub))
	}
	switch strings.ToLower(strings.TrimSpace(cfg.CI.Mode)) {
	case config.CIModeWarnOnly, config.CIModeEnforced:
	default:
		errs = append(errs, fmt.Errorf("ci.mode must be one of: %s, %s", config.CIModeWarnOnly, config.CIModeEnforced))
	}
	if !cfg.CI.GenerateWorkflows {
		warnings = append(warnings, "ci.generate_workflows=false; CI security workflows will not be generated")
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Reporting.Format)) {
	case config.FormatText, config.FormatJSON:
	default:
		errs = append(errs, fmt.Errorf("reporting.format must be one of: %s, %s", config.FormatText, config.FormatJSON))
	}
	if severityRank[strings.ToLower(strings.TrimSpace(cfg.Reporting.MinimumSeverity))] == 0 {
		errs = append(errs, fmt.Errorf("reporting.minimum_severity must be one of: low, medium, high, critical"))
	}
	if strings.TrimSpace(cfg.Reporting.OutputPath) == "" {
		errs = append(errs, fmt.Errorf("reporting.output_path is required"))
	}

	if cfg.Observability.Enable {
		if strings.TrimSpace(cfg.Observability.PanelBind) == "" {
			errs = append(errs, fmt.Errorf("observability.panel_bind is required when observability.enable=true"))
		}
		if strings.TrimSpace(cfg.Observability.LocalDataDir) == "" {
			errs = append(errs, fmt.Errorf("observability.local_data_dir is required when observability.enable=true"))
		}
		if cfg.Observability.HostMetrics && !containsString(cfg.Observability.LogSources, "journald") {
			warnings = append(warnings, "observability.host_metrics=true but journald is not listed in observability.log_sources")
		}
	}

	if cfg.Alerts.Enabled {
		if strings.TrimSpace(cfg.Alerts.WebhookURL) == "" && strings.TrimSpace(cfg.Alerts.Email) == "" && strings.TrimSpace(cfg.Alerts.SlackURL) == "" {
			warnings = append(warnings, "alerts.enabled=true but no webhook_url, email, or slack_url is configured")
		}
		if cfg.Alerts.Thresholds.SSHFailures15m <= 0 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.ssh_failures_15m must be > 0"))
		}
		if cfg.Alerts.Thresholds.Bans15m <= 0 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.bans_15m must be > 0"))
		}
		if cfg.Alerts.Thresholds.NginxErrors15m <= 0 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.nginx_errors_15m must be > 0"))
		}
		if cfg.Alerts.Thresholds.ContainerRestarts < 0 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.container_restarts must be >= 0"))
		}
		if cfg.Alerts.Thresholds.DiskPercentUsed <= 0 || cfg.Alerts.Thresholds.DiskPercentUsed > 100 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.disk_percent_used must be between 1 and 100"))
		}
		if cfg.Alerts.Thresholds.CertExpiryDays <= 0 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.cert_expiry_days must be > 0"))
		}
	}

	for _, rawURL := range cfg.AppInventory.HealthcheckURLs {
		if strings.TrimSpace(rawURL) == "" {
			continue
		}
		if err := validateURL("app_inventory.healthcheck_urls", rawURL); err != nil {
			errs = append(errs, err)
		}
	}

	if hasLegacyManagedDeploy(cfg) {
		warnings = append(warnings, "legacy managed deploy fields detected; v2 treats them as migration hints only")
	}

	return warnings, errs
}

func validateURL(field string, raw string) error {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s must be a valid URL", field)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s must include scheme and host", field)
	}
	return nil
}

func hasLegacyManagedDeploy(cfg config.Config) bool {
	return strings.TrimSpace(cfg.LegacyApp.ComposeFile) != "" ||
		strings.TrimSpace(cfg.LegacyApp.UpstreamURL) != "" ||
		strings.TrimSpace(cfg.LegacyApp.EnvFile) != "" ||
		strings.TrimSpace(cfg.LegacyDomain.FQDN) != "" ||
		cfg.LegacyTLS.Enabled ||
		strings.TrimSpace(cfg.LegacyDashboard.Path) != ""
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
}
