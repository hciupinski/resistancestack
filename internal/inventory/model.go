package inventory

import (
	"time"

	"github.com/hciupinski/resistancestack/internal/ci"
)

type Snapshot struct {
	CollectedAt      time.Time         `json:"collected_at"`
	CurrentSessionIP string            `json:"current_session_ip"`
	Host             HostInfo          `json:"host"`
	Proxy            ProxyInfo         `json:"proxy"`
	Runtime          RuntimeInfo       `json:"runtime"`
	ExposedPorts     []PortInfo        `json:"exposed_ports"`
	TLSCertificates  []TLSCertificate  `json:"tls_certificates"`
	SSHUsers         []string          `json:"ssh_users"`
	SudoUsers        []string          `json:"sudo_users"`
	PasswordlessSudo bool              `json:"passwordless_sudo"`
	UFW              ServiceState      `json:"ufw"`
	Fail2ban         ServiceState      `json:"fail2ban"`
	LogLocations     []string          `json:"log_locations"`
	Containers       []ContainerInfo   `json:"containers"`
	Repo             RepoInfo          `json:"repo"`
	Observability    ObservabilityInfo `json:"observability"`
}

type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Kernel   string `json:"kernel"`
}

type ProxyInfo struct {
	Kind   string   `json:"kind"`
	Active bool     `json:"active"`
	Notes  []string `json:"notes"`
}

type RuntimeInfo struct {
	Kind         string   `json:"kind"`
	ComposeFiles []string `json:"compose_files"`
	SystemdUnits []string `json:"systemd_units"`
}

type PortInfo struct {
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	Address string `json:"address"`
	Public  bool   `json:"public"`
}

type TLSCertificate struct {
	Path      string   `json:"path"`
	Names     []string `json:"names"`
	ExpiresAt string   `json:"expires_at"`
	Valid     bool     `json:"valid"`
}

type TLSCertificateStatus string

const (
	TLSCertificateStatusMissing TLSCertificateStatus = "missing"
	TLSCertificateStatusInvalid TLSCertificateStatus = "invalid"
	TLSCertificateStatusValid   TLSCertificateStatus = "valid"
)

type ServiceState struct {
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"`
}

type ContainerInfo struct {
	Name     string `json:"name"`
	Image    string `json:"image"`
	Status   string `json:"status"`
	Restarts int    `json:"restarts"`
}

type RepoInfo struct {
	GitHubWorkflows []string       `json:"github_workflows"`
	ComposeFiles    []string       `json:"compose_files"`
	NginxPaths      []string       `json:"nginx_paths"`
	SystemdUnits    []string       `json:"systemd_units"`
	Technologies    []string       `json:"technologies"`
	TechProfile     ci.TechProfile `json:"tech_profile"`
}

type ObservabilityInfo struct {
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"`
}
