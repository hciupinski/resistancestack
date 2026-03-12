package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ProjectName string          `yaml:"project_name"`
	Server      ServerConfig    `yaml:"server"`
	Domain      DomainConfig    `yaml:"domain"`
	App         AppConfig       `yaml:"app"`
	TLS         TLSConfig       `yaml:"tls"`
	Security    SecurityConfig  `yaml:"security"`
	Alerts      AlertsConfig    `yaml:"alerts"`
	Dashboard   DashboardConfig `yaml:"dashboard"`
	CI          CIConfig        `yaml:"ci"`
}

type ServerConfig struct {
	Host            string `yaml:"host"`
	SSHUser         string `yaml:"ssh_user"`
	SSHPort         int    `yaml:"ssh_port"`
	PrivateKeyPath  string `yaml:"private_key_path"`
	HostKeyChecking string `yaml:"host_key_checking"`
	KnownHostsPath  string `yaml:"known_hosts_path"`
}

type DomainConfig struct {
	FQDN string `yaml:"fqdn"`
}

type AppConfig struct {
	HealthcheckURL string `yaml:"healthcheck_url"`
	ComposeFile    string `yaml:"compose_file"`
	EnvFile        string `yaml:"env_file"`
	UpstreamURL    string `yaml:"upstream_url"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Email   string `yaml:"email"`
	Staging bool   `yaml:"staging"`
}

type SecurityConfig struct {
	Profile        string   `yaml:"profile"`
	AdminAllowlist []string `yaml:"admin_allowlist"`
}

type AlertsConfig struct {
	WebhookURL string     `yaml:"webhook_url"`
	Thresholds Thresholds `yaml:"thresholds"`
	Enabled    bool       `yaml:"enabled"`
}

type DashboardConfig struct {
	Path      string          `yaml:"path"`
	BasicAuth BasicAuthConfig `yaml:"basic_auth"`
}

type BasicAuthConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Thresholds struct {
	SSHFail5m    int `yaml:"ssh_fail_5m"`
	BansPerHour  int `yaml:"bans_per_hour"`
	ProbePerHour int `yaml:"probe_per_hour"`
	Upstream5m   int `yaml:"upstream_5m"`
}

type CIConfig struct {
	GitHubActions bool `yaml:"github_actions"`
}

func Default(projectName string) Config {
	return Config{
		ProjectName: projectName,
		Server: ServerConfig{
			Host:            "1.2.3.4",
			SSHUser:         "deployer",
			SSHPort:         22,
			PrivateKeyPath:  "~/.ssh/id_ed25519",
			HostKeyChecking: "strict",
			KnownHostsPath:  "~/.ssh/known_hosts",
		},
		Domain: DomainConfig{
			FQDN: "app.example.com",
		},
		App: AppConfig{
			HealthcheckURL: "http://127.0.0.1:8080/health",
			ComposeFile:    "./docker-compose.app.yml",
			EnvFile:        "./.env.app",
			UpstreamURL:    "http://127.0.0.1:8080",
		},
		TLS: TLSConfig{
			Enabled: true,
			Email:   "admin@example.com",
			Staging: false,
		},
		Security: SecurityConfig{
			Profile:        "balanced",
			AdminAllowlist: []string{"203.0.113.10/32"},
		},
		Alerts: AlertsConfig{
			WebhookURL: "https://hooks.example.com/incident",
			Enabled:    true,
			Thresholds: Thresholds{
				SSHFail5m:    100,
				BansPerHour:  20,
				ProbePerHour: 150,
				Upstream5m:   10,
			},
		},
		Dashboard: DashboardConfig{
			Path: "/_resistack/status/",
			BasicAuth: BasicAuthConfig{
				Enabled:  true,
				Username: "resistack",
				Password: "change-me-now",
			},
		},
		CI: CIConfig{
			GitHubActions: true,
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

	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}
