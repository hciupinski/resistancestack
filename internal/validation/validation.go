package validation

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
)

func Check(cfg config.Config) (warnings []string, errs []error) {
	if strings.TrimSpace(cfg.ProjectName) == "" {
		errs = append(errs, fmt.Errorf("project_name is required"))
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

	if strings.TrimSpace(cfg.Domain.FQDN) == "" {
		errs = append(errs, fmt.Errorf("domain.fqdn is required"))
	}

	if strings.TrimSpace(cfg.App.ComposeFile) == "" {
		errs = append(errs, fmt.Errorf("app.compose_file is required"))
	}
	if envFile := strings.TrimSpace(cfg.App.EnvFile); envFile == "" {
		warnings = append(warnings, "app.env_file is empty; compose deployments will run without an env file")
	}
	if strings.TrimSpace(cfg.App.UpstreamURL) == "" {
		errs = append(errs, fmt.Errorf("app.upstream_url is required"))
	} else if err := validateURL("app.upstream_url", cfg.App.UpstreamURL); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(cfg.App.HealthcheckURL) == "" {
		warnings = append(warnings, "app.healthcheck_url is empty; status checks will be degraded")
	} else if err := validateURL("app.healthcheck_url", cfg.App.HealthcheckURL); err != nil {
		errs = append(errs, err)
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Security.Profile)) {
	case "balanced", "strict", "lenient":
	default:
		errs = append(errs, fmt.Errorf("security.profile must be one of: balanced, strict, lenient"))
	}

	if len(cfg.Security.AdminAllowlist) == 0 {
		warnings = append(warnings, "security.admin_allowlist is empty; SSH will not be IP constrained by default")
	}
	for _, entry := range cfg.Security.AdminAllowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, err := netip.ParsePrefix(entry); err != nil {
			errs = append(errs, fmt.Errorf("security.admin_allowlist contains invalid CIDR %q", entry))
		}
	}

	if cfg.TLS.Enabled {
		tlsEmail := strings.TrimSpace(cfg.TLS.Email)
		if tlsEmail == "" {
			errs = append(errs, fmt.Errorf("tls.email is required when tls.enabled=true"))
		}
		if tlsEmail != "" && !strings.Contains(tlsEmail, "@") {
			errs = append(errs, fmt.Errorf("tls.email must be a valid email address"))
		}
		if cfg.TLS.Staging {
			warnings = append(warnings, "tls.staging=true; Let's Encrypt test certificate will be issued")
		}
	}

	if cfg.Alerts.Enabled {
		if strings.TrimSpace(cfg.Alerts.WebhookURL) == "" {
			warnings = append(warnings, "alerts.enabled=true but alerts.webhook_url is empty")
		}

		if cfg.Alerts.Thresholds.SSHFail5m <= 0 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.ssh_fail_5m must be > 0"))
		}
		if cfg.Alerts.Thresholds.BansPerHour <= 0 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.bans_per_hour must be > 0"))
		}
		if cfg.Alerts.Thresholds.ProbePerHour <= 0 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.probe_per_hour must be > 0"))
		}
		if cfg.Alerts.Thresholds.Upstream5m <= 0 {
			errs = append(errs, fmt.Errorf("alerts.thresholds.upstream_5m must be > 0"))
		}
	}

	if path := strings.TrimSpace(cfg.Dashboard.Path); path == "" {
		errs = append(errs, fmt.Errorf("dashboard.path is required"))
	} else if !strings.HasPrefix(path, "/") || !strings.HasSuffix(path, "/") {
		errs = append(errs, fmt.Errorf("dashboard.path must start and end with /"))
	}

	if cfg.Dashboard.BasicAuth.Enabled {
		if strings.TrimSpace(cfg.Dashboard.BasicAuth.Username) == "" {
			errs = append(errs, fmt.Errorf("dashboard.basic_auth.username is required when dashboard.basic_auth.enabled=true"))
		}
		password := strings.TrimSpace(cfg.Dashboard.BasicAuth.Password)
		if password == "" {
			errs = append(errs, fmt.Errorf("dashboard.basic_auth.password is required when dashboard.basic_auth.enabled=true"))
		} else if password == "change-me-now" {
			warnings = append(warnings, "dashboard.basic_auth.password uses the default placeholder; rotate it before production")
		}
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
