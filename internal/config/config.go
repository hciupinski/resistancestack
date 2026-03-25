package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	ModeAuditThenApply               = "audit_then_apply"
	CIProviderGitHub                 = "github_actions"
	CIModeWarnOnly                   = "warn-only"
	CIModeEnforced                   = "enforced"
	FormatText                       = "text"
	FormatJSON                       = "json"
	SeverityLow                      = "low"
	SeverityMedium                   = "medium"
	SeverityHigh                     = "high"
	SeverityCritical                 = "critical"
	OperatorAccessModePublicHardened = "public_hardened"
	OperatorAccessModeAllowlistOnly  = "allowlist_only"
)

type Config struct {
	ProjectName     string                `yaml:"project_name"`
	Mode            ModeConfig            `yaml:"mode"`
	Server          ServerConfig          `yaml:"server"`
	HostHardening   HostHardeningConfig   `yaml:"host_hardening"`
	AppInventory    AppInventoryConfig    `yaml:"app_inventory"`
	Observability   ObservabilityConfig   `yaml:"observability"`
	CI              CIConfig              `yaml:"ci"`
	Reporting       ReportingConfig       `yaml:"reporting"`
	Alerts          AlertsConfig          `yaml:"alerts"`
	LegacySecurity  LegacySecurityConfig  `yaml:"security,omitempty"`
	LegacyApp       LegacyAppConfig       `yaml:"app,omitempty"`
	LegacyDomain    LegacyDomainConfig    `yaml:"domain,omitempty"`
	LegacyTLS       LegacyTLSConfig       `yaml:"tls,omitempty"`
	LegacyDashboard LegacyDashboardConfig `yaml:"dashboard,omitempty"`
}

type ModeConfig struct {
	Strategy string `yaml:"strategy"`
}

type ServerConfig struct {
	Host            string `yaml:"host"`
	SSHUser         string `yaml:"ssh_user"`
	SSHPort         int    `yaml:"ssh_port"`
	PrivateKeyPath  string `yaml:"private_key_path"`
	HostKeyChecking string `yaml:"host_key_checking"`
	KnownHostsPath  string `yaml:"known_hosts_path"`
}

type HostHardeningConfig struct {
	Enabled                  bool               `yaml:"enabled"`
	SSHHardening             SSHHardeningConfig `yaml:"ssh_hardening"`
	UFWPolicy                UFWPolicyConfig    `yaml:"ufw_policy"`
	Fail2ban                 Fail2banConfig     `yaml:"fail2ban"`
	AutomaticSecurityUpdates bool               `yaml:"automatic_security_updates"`
	CheckDeployUser          bool               `yaml:"check_deploy_user"`
	CheckDockerDaemon        bool               `yaml:"check_docker_daemon"`
	BackupDir                string             `yaml:"backup_dir"`
}

type SSHHardeningConfig struct {
	DisableRootLogin        bool     `yaml:"disable_root_login"`
	DisablePasswordAuth     bool     `yaml:"disable_password_auth"`
	AllowUsers              []string `yaml:"allow_users,omitempty"`
	MaxAuthTries            int      `yaml:"max_auth_tries"`
	LoginGraceTimeSeconds   int      `yaml:"login_grace_time_seconds"`
	GuardCurrentOperator    bool     `yaml:"guard_current_operator"`
	RequirePasswordlessSudo bool     `yaml:"require_passwordless_sudo"`
}

type UFWPolicyConfig struct {
	Enabled                bool     `yaml:"enabled"`
	DefaultIncoming        string   `yaml:"default_incoming"`
	DefaultOutgoing        string   `yaml:"default_outgoing"`
	AllowedTCPPorts        []int    `yaml:"allowed_tcp_ports,omitempty"`
	AllowedUDPPorts        []int    `yaml:"allowed_udp_ports,omitempty"`
	AdminAllowlist         []string `yaml:"admin_allowlist,omitempty"`
	OperatorAccessMode     string   `yaml:"operator_access_mode"`
	PreserveCurrentSession bool     `yaml:"preserve_current_session"`
}

type Fail2banConfig struct {
	Enabled         bool   `yaml:"enabled"`
	BanTime         string `yaml:"ban_time"`
	FindTime        string `yaml:"find_time"`
	MaxRetry        int    `yaml:"max_retry"`
	RecidiveEnabled bool   `yaml:"recidive_enabled"`
	RecidiveBanTime string `yaml:"recidive_ban_time"`
}

type AppInventoryConfig struct {
	ComposePaths    []string `yaml:"compose_paths,omitempty"`
	NginxPaths      []string `yaml:"nginx_paths,omitempty"`
	SystemdUnits    []string `yaml:"systemd_units,omitempty"`
	Domains         []string `yaml:"domains,omitempty"`
	HealthcheckURLs []string `yaml:"healthcheck_urls,omitempty"`
}

type ObservabilityConfig struct {
	Enable       bool     `yaml:"enable"`
	LogSources   []string `yaml:"log_sources,omitempty"`
	HostMetrics  bool     `yaml:"host_metrics"`
	PanelBind    string   `yaml:"panel_bind"`
	LocalDataDir string   `yaml:"local_data_dir"`
}

type CIConfig struct {
	Provider          string        `yaml:"provider"`
	GenerateWorkflows bool          `yaml:"generate_workflows"`
	Mode              string        `yaml:"mode"`
	Schedule          string        `yaml:"schedule"`
	Scans             CIScansConfig `yaml:"scans"`
}

type CIScansConfig struct {
	Dependency bool `yaml:"dependency"`
	Image      bool `yaml:"image"`
	SBOM       bool `yaml:"sbom"`
	Secrets    bool `yaml:"secrets"`
	License    bool `yaml:"license"`
	OSV        bool `yaml:"osv"`
}

type ReportingConfig struct {
	OutputPath      string `yaml:"output_path"`
	Format          string `yaml:"format"`
	MinimumSeverity string `yaml:"minimum_severity"`
}

type AlertsConfig struct {
	WebhookURL string          `yaml:"webhook_url"`
	Email      string          `yaml:"email"`
	SlackURL   string          `yaml:"slack_url"`
	Thresholds AlertThresholds `yaml:"thresholds"`
	Enabled    bool            `yaml:"enabled"`
}

type AlertThresholds struct {
	SSHFailures15m    int `yaml:"ssh_failures_15m"`
	Bans15m           int `yaml:"bans_15m"`
	NginxErrors15m    int `yaml:"nginx_errors_15m"`
	ContainerRestarts int `yaml:"container_restarts"`
	DiskPercentUsed   int `yaml:"disk_percent_used"`
	CertExpiryDays    int `yaml:"cert_expiry_days"`
}

// Deprecated legacy fields preserved for migration from the deploy-centric v1 model.
type LegacySecurityConfig struct {
	Profile        string   `yaml:"profile,omitempty"`
	AdminAllowlist []string `yaml:"admin_allowlist,omitempty"`
}

type LegacyAppConfig struct {
	HealthcheckURL string `yaml:"healthcheck_url,omitempty"`
	ComposeFile    string `yaml:"compose_file,omitempty"`
	EnvFile        string `yaml:"env_file,omitempty"`
	UpstreamURL    string `yaml:"upstream_url,omitempty"`
}

type LegacyDomainConfig struct {
	FQDN string `yaml:"fqdn,omitempty"`
}

type LegacyTLSConfig struct {
	Enabled bool   `yaml:"enabled,omitempty"`
	Email   string `yaml:"email,omitempty"`
	Staging bool   `yaml:"staging,omitempty"`
}

type LegacyDashboardConfig struct {
	Path      string                `yaml:"path,omitempty"`
	BasicAuth LegacyBasicAuthConfig `yaml:"basic_auth,omitempty"`
}

type LegacyBasicAuthConfig struct {
	Enabled  bool   `yaml:"enabled,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

func Default(projectName string) Config {
	return Config{
		ProjectName: projectName,
		Mode: ModeConfig{
			Strategy: ModeAuditThenApply,
		},
		Server: ServerConfig{
			Host:            "1.2.3.4",
			SSHUser:         "deployer",
			SSHPort:         22,
			PrivateKeyPath:  "~/.ssh/id_ed25519",
			HostKeyChecking: "strict",
			KnownHostsPath:  "~/.ssh/known_hosts",
		},
		HostHardening: HostHardeningConfig{
			Enabled: true,
			SSHHardening: SSHHardeningConfig{
				DisableRootLogin:        true,
				DisablePasswordAuth:     true,
				MaxAuthTries:            4,
				LoginGraceTimeSeconds:   30,
				GuardCurrentOperator:    true,
				RequirePasswordlessSudo: true,
			},
			UFWPolicy: UFWPolicyConfig{
				Enabled:                true,
				DefaultIncoming:        "deny",
				DefaultOutgoing:        "allow",
				AllowedTCPPorts:        []int{22, 80, 443},
				AdminAllowlist:         []string{},
				OperatorAccessMode:     OperatorAccessModePublicHardened,
				PreserveCurrentSession: true,
			},
			Fail2ban: Fail2banConfig{
				Enabled:         true,
				BanTime:         "1h",
				FindTime:        "10m",
				MaxRetry:        5,
				RecidiveEnabled: true,
				RecidiveBanTime: "24h",
			},
			AutomaticSecurityUpdates: true,
			CheckDeployUser:          true,
			CheckDockerDaemon:        true,
			BackupDir:                "/var/lib/resistack/backups/host",
		},
		AppInventory: AppInventoryConfig{
			ComposePaths:    []string{"docker-compose.yml", "docker-compose.prod.yml", "compose.yml"},
			NginxPaths:      []string{"/etc/nginx/sites-enabled", "/etc/nginx/conf.d"},
			SystemdUnits:    []string{"nginx", "docker", "fail2ban"},
			Domains:         []string{"app.example.com"},
			HealthcheckURLs: []string{"http://127.0.0.1:8080/health"},
		},
		Observability: ObservabilityConfig{
			Enable:       true,
			LogSources:   []string{"journald", "nginx", "docker", "fail2ban"},
			HostMetrics:  true,
			PanelBind:    "127.0.0.1:9400",
			LocalDataDir: "/var/lib/resistack/observability",
		},
		CI: CIConfig{
			Provider:          CIProviderGitHub,
			GenerateWorkflows: true,
			Mode:              CIModeWarnOnly,
			Schedule:          "24 3 * * *",
			Scans: CIScansConfig{
				Dependency: true,
				Image:      true,
				SBOM:       true,
				Secrets:    true,
				License:    true,
				OSV:        true,
			},
		},
		Reporting: ReportingConfig{
			OutputPath:      "./.resistack/reports",
			Format:          FormatText,
			MinimumSeverity: SeverityLow,
		},
		Alerts: AlertsConfig{
			WebhookURL: "https://hooks.example.com/security",
			Email:      "security@example.com",
			SlackURL:   "https://hooks.slack.com/services/T000/B000/XXX",
			Enabled:    true,
			Thresholds: AlertThresholds{
				SSHFailures15m:    25,
				Bans15m:           10,
				NginxErrors15m:    30,
				ContainerRestarts: 3,
				DiskPercentUsed:   85,
				CertExpiryDays:    21,
			},
		},
	}
}

func Save(path string, cfg Config) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}

	cfg := Default("resistack")
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.ProjectName == "" {
		cfg.ProjectName = "resistack"
	}
	normalizeLegacy(&cfg)
	return cfg, nil
}

func normalizeLegacy(cfg *Config) {
	if len(cfg.HostHardening.UFWPolicy.AdminAllowlist) == 0 && len(cfg.LegacySecurity.AdminAllowlist) > 0 {
		cfg.HostHardening.UFWPolicy.AdminAllowlist = append([]string{}, cfg.LegacySecurity.AdminAllowlist...)
	}
	if len(cfg.AppInventory.ComposePaths) == 0 && cfg.LegacyApp.ComposeFile != "" {
		cfg.AppInventory.ComposePaths = []string{cfg.LegacyApp.ComposeFile}
	}
	if len(cfg.AppInventory.HealthcheckURLs) == 0 && cfg.LegacyApp.HealthcheckURL != "" {
		cfg.AppInventory.HealthcheckURLs = []string{cfg.LegacyApp.HealthcheckURL}
	}
	if len(cfg.AppInventory.Domains) == 0 && cfg.LegacyDomain.FQDN != "" {
		cfg.AppInventory.Domains = []string{cfg.LegacyDomain.FQDN}
	}
}
