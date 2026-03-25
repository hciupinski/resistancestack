package config

import (
	"fmt"
	"os"
	"strings"

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

type InitResult struct {
	Created bool
	Added   []string
}

func EnsureDefaultConfig(path string, projectName string, overwrite bool) (InitResult, error) {
	doc, err := DefaultDocument(projectName)
	if err != nil {
		return InitResult{}, err
	}

	if overwrite {
		if err := SaveDocument(path, doc); err != nil {
			return InitResult{}, err
		}
		return InitResult{Created: true}, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := SaveDocument(path, doc); err != nil {
				return InitResult{}, err
			}
			return InitResult{Created: true}, nil
		}
		return InitResult{}, fmt.Errorf("read %s: %w", path, err)
	}

	if strings.TrimSpace(string(raw)) == "" {
		if err := SaveDocument(path, doc); err != nil {
			return InitResult{}, err
		}
		return InitResult{Created: true}, nil
	}

	var existing yaml.Node
	if err := yaml.Unmarshal(raw, &existing); err != nil {
		return InitResult{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(existing.Content) == 0 {
		if err := SaveDocument(path, doc); err != nil {
			return InitResult{}, err
		}
		return InitResult{Created: true}, nil
	}

	added := mergeMissingDefaults(&existing, doc)
	if len(added) == 0 {
		return InitResult{}, nil
	}
	if err := SaveDocument(path, &existing); err != nil {
		return InitResult{}, err
	}
	return InitResult{Added: added}, nil
}

func DefaultDocument(projectName string) (*yaml.Node, error) {
	cfg := Default(projectName)
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal default config: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode default config node: %w", err)
	}
	annotateDefaultComments(&doc)
	return &doc, nil
}

func SaveDocument(path string, doc *yaml.Node) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		_ = encoder.Close()
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("close encoder for %s: %w", path, err)
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

var defaultLineComments = map[string]string{
	"project_name":             "Identifier used in reports, generated files, and remote assets.",
	"mode.strategy":            "Workflow mode. Options: audit_then_apply.",
	"server.host":              "Target VPS hostname or IP.",
	"server.ssh_user":          "SSH user used by resistack to connect to the server.",
	"server.ssh_port":          "SSH port for remote access.",
	"server.private_key_path":  "Private key used for SSH authentication.",
	"server.host_key_checking": "SSH host key policy. Options: strict, accept-new.",
	"server.known_hosts_path":  "Known hosts file used when strict checking is enabled.",
	"host_hardening.enabled":   "Enable baseline host hardening.",
	"host_hardening.ssh_hardening.disable_root_login":        "Disable direct SSH login for root.",
	"host_hardening.ssh_hardening.disable_password_auth":     "Require key-based SSH authentication.",
	"host_hardening.ssh_hardening.allow_users[]":             "User explicitly allowed to log in via SSH.",
	"host_hardening.ssh_hardening.max_auth_tries":            "Maximum SSH authentication attempts per connection.",
	"host_hardening.ssh_hardening.login_grace_time_seconds":  "Seconds allowed to complete SSH login before disconnect.",
	"host_hardening.ssh_hardening.guard_current_operator":    "Protect the active operator session during hardening.",
	"host_hardening.ssh_hardening.require_passwordless_sudo": "Require non-interactive sudo for host changes.",
	"host_hardening.ufw_policy.enabled":                      "Enable UFW baseline firewall rules.",
	"host_hardening.ufw_policy.default_incoming":             "Default inbound firewall policy. Options: allow, deny, reject.",
	"host_hardening.ufw_policy.default_outgoing":             "Default outbound firewall policy. Options: allow, deny, reject.",
	"host_hardening.ufw_policy.operator_access_mode":         "SSH operator access strategy. Options: public_hardened, allowlist_only.",
	"host_hardening.ufw_policy.preserve_current_session":     "Temporarily preserve the current SSH session when needed.",
	"host_hardening.ufw_policy.allowed_tcp_ports[]":          "TCP port kept reachable on the host.",
	"host_hardening.ufw_policy.allowed_udp_ports[]":          "UDP port kept reachable on the host.",
	"host_hardening.ufw_policy.admin_allowlist[]":            "Optional static CIDR allowlist for SSH operators.",
	"host_hardening.fail2ban.enabled":                        "Enable fail2ban for SSH abuse protection.",
	"host_hardening.fail2ban.ban_time":                       "How long a source stays banned after repeated failures.",
	"host_hardening.fail2ban.find_time":                      "Window used to count repeated failures.",
	"host_hardening.fail2ban.max_retry":                      "Failed attempts allowed before a ban.",
	"host_hardening.fail2ban.recidive_enabled":               "Enable longer recidive bans for repeat offenders.",
	"host_hardening.fail2ban.recidive_ban_time":              "Ban duration for recidive offenders.",
	"host_hardening.automatic_security_updates":              "Enable automatic security updates on the host.",
	"host_hardening.check_deploy_user":                       "Verify the configured SSH user exists on the server.",
	"host_hardening.check_docker_daemon":                     "Inspect docker daemon settings for risky listeners.",
	"host_hardening.backup_dir":                              "Directory used for host-hardening backups and rollback.",
	"app_inventory.compose_paths[]":                          "Compose path hint used during repo and host inventory.",
	"app_inventory.nginx_paths[]":                            "Nginx path hint used during brownfield detection.",
	"app_inventory.systemd_units[]":                          "Systemd unit hint used during runtime detection.",
	"app_inventory.domains[]":                                "Domain hint used for ingress and TLS inventory.",
	"app_inventory.healthcheck_urls[]":                       "Optional health endpoints used by audit and observability.",
	"observability.enable":                                   "Enable local security observability baseline.",
	"observability.log_sources[]":                            "Log source collected by the observability baseline.",
	"observability.host_metrics":                             "Collect host-level runtime metrics and disk pressure.",
	"observability.panel_bind":                               "Local bind address for the observability panel.",
	"observability.local_data_dir":                           "Directory used for observability snapshots and local panel data.",
	"ci.provider":                                            "CI provider used by generated workflows. Options: github_actions.",
	"ci.generate_workflows":                                  "Generate standalone security workflows in the repo.",
	"ci.mode":                                                "Workflow enforcement mode. Options: warn-only, enforced.",
	"ci.schedule":                                            "Cron schedule for recurring security scans.",
	"ci.scans.dependency":                                    "Enable dependency and SCA workflow generation.",
	"ci.scans.image":                                         "Enable container and image scan workflow generation.",
	"ci.scans.sbom":                                          "Enable SBOM generation workflow.",
	"ci.scans.secrets":                                       "Enable secret scanning workflow.",
	"ci.scans.license":                                       "Enable license inventory checks in CI.",
	"ci.scans.osv":                                           "Enable OSV-based vulnerability scanning.",
	"reporting.output_path":                                  "Directory used to store generated reports.",
	"reporting.format":                                       "Report format. Options: text, json.",
	"reporting.minimum_severity":                             "Lowest severity included in generated reports. Options: low, medium, high, critical.",
	"alerts.webhook_url":                                     "Webhook endpoint for alert delivery.",
	"alerts.email":                                           "Email target used for alert routing metadata.",
	"alerts.slack_url":                                       "Slack webhook used for alert delivery.",
	"alerts.enabled":                                         "Enable alert generation for observability findings.",
	"alerts.thresholds.ssh_failures_15m":                     "SSH failures in 15 minutes required to trigger an alert.",
	"alerts.thresholds.bans_15m":                             "fail2ban bans in 15 minutes required to trigger an alert.",
	"alerts.thresholds.nginx_errors_15m":                     "Nginx 4xx and 5xx events in 15 minutes required to trigger an alert.",
	"alerts.thresholds.container_restarts":                   "Container restart count required to trigger an alert.",
	"alerts.thresholds.disk_percent_used":                    "Disk usage percentage required to trigger an alert.",
	"alerts.thresholds.cert_expiry_days":                     "Certificate days-to-expiry required to trigger an alert.",
}

func annotateDefaultComments(doc *yaml.Node) {
	if doc == nil || len(doc.Content) == 0 {
		return
	}
	annotateNode(doc.Content[0], "")
}

func annotateNode(node *yaml.Node, path string) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			childPath := keyNode.Value
			if path != "" {
				childPath = path + "." + keyNode.Value
			}
			if comment, ok := defaultLineComments[childPath]; ok {
				valueNode.LineComment = comment
			}
			annotateNode(valueNode, childPath)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if comment, ok := defaultLineComments[path+"[]"]; ok {
				child.LineComment = comment
			}
			annotateNode(child, path+"[]")
		}
	}
}

func mergeMissingDefaults(existingDoc *yaml.Node, defaultDoc *yaml.Node) []string {
	if existingDoc.Kind == yaml.DocumentNode && len(existingDoc.Content) > 0 {
		existingDoc = existingDoc.Content[0]
	}
	if defaultDoc.Kind == yaml.DocumentNode && len(defaultDoc.Content) > 0 {
		defaultDoc = defaultDoc.Content[0]
	}
	return mergeMappingNode(existingDoc, defaultDoc, "")
}

func mergeMappingNode(existing *yaml.Node, defaults *yaml.Node, path string) []string {
	if existing.Kind != yaml.MappingNode || defaults.Kind != yaml.MappingNode {
		return nil
	}

	added := []string{}
	for i := 0; i < len(defaults.Content); i += 2 {
		defaultKey := defaults.Content[i]
		defaultValue := defaults.Content[i+1]
		childPath := defaultKey.Value
		if path != "" {
			childPath = path + "." + defaultKey.Value
		}

		index := mappingIndex(existing, defaultKey.Value)
		if index == -1 {
			existing.Content = append(existing.Content, cloneNode(defaultKey), cloneNode(defaultValue))
			added = append(added, childPath)
			continue
		}

		existingValue := existing.Content[index+1]
		if existingValue.Kind == yaml.MappingNode && defaultValue.Kind == yaml.MappingNode {
			added = append(added, mergeMappingNode(existingValue, defaultValue, childPath)...)
		}
	}
	return added
}

func mappingIndex(node *yaml.Node, key string) int {
	if node.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return i
		}
	}
	return -1
}

func cloneNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	clone := *node
	clone.Content = make([]*yaml.Node, 0, len(node.Content))
	for _, child := range node.Content {
		clone.Content = append(clone.Content, cloneNode(child))
	}
	return &clone
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
