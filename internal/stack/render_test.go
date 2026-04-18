package stack

import (
	"bytes"
	"testing"
	"time"

	"github.com/hciupinski/resistancestack/internal/audit"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

func TestRenderInventory(t *testing.T) {
	var out bytes.Buffer
	snapshot := inventory.Snapshot{
		Host:             inventory.HostInfo{Hostname: "demo", OS: "ubuntu"},
		Proxy:            inventory.ProxyInfo{Kind: "nginx"},
		Runtime:          inventory.RuntimeInfo{Kind: "docker-compose"},
		UFW:              inventory.ServiceState{Status: "active"},
		Fail2ban:         inventory.ServiceState{Status: "active"},
		PasswordlessSudo: true,
		Repo: inventory.RepoInfo{
			Technologies:    []string{"node", "docker"},
			GitHubWorkflows: []string{"build.yml", "security.yml"},
		},
	}

	renderInventory(&out, snapshot)

	const want = "" +
		"Host: demo\n" +
		"OS: ubuntu\n" +
		"Proxy: nginx\n" +
		"Runtime: docker-compose\n" +
		"UFW: active\n" +
		"Fail2ban: active\n" +
		"Passwordless sudo: true\n" +
		"Repo technologies: node, docker\n" +
		"GitHub workflows: build.yml, security.yml\n"

	if got := out.String(); got != want {
		t.Fatalf("unexpected inventory output:\n%s", got)
	}
}

func TestFormatStatus(t *testing.T) {
	snapshot := inventory.Snapshot{
		Host:          inventory.HostInfo{Hostname: "demo", OS: "ubuntu"},
		Proxy:         inventory.ProxyInfo{Kind: "nginx"},
		Runtime:       inventory.RuntimeInfo{Kind: "docker-compose"},
		UFW:           inventory.ServiceState{Status: "active"},
		Fail2ban:      inventory.ServiceState{Status: "active"},
		Observability: inventory.ObservabilityInfo{
			Enabled:         true,
			Status:          "enabled",
			DashboardURL:    "http://127.0.0.1:9400/",
			CredentialsPath: "/var/lib/resistack/observability/grafana-admin.txt",
			LastSnapshotAt:  "2026-04-18T12:00:00Z",
			SnapshotService: inventory.ServiceState{Status: "active"},
			SnapshotTimer:   inventory.ServiceState{Status: "active"},
			GrafanaService:  inventory.ServiceState{Status: "active"},
			LokiService:     inventory.ServiceState{Status: "active"},
			AlloyService:    inventory.ServiceState{Status: "active"},
		},
		Containers:    []inventory.ContainerInfo{{Name: "api", Status: "running", Restarts: 1}},
	}
	report := audit.Report{
		GeneratedAt: time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC),
		Summary: audit.Summary{
			BySeverity: map[string]int{
				config.SeverityCritical: 1,
				config.SeverityHigh:     2,
				config.SeverityMedium:   3,
				config.SeverityLow:      4,
			},
			TopSeverity: config.SeverityCritical,
		},
		Findings: []audit.Finding{
			{Severity: config.SeverityCritical, Description: "docker api exposed"},
			{Severity: config.SeverityHigh, Description: "fail2ban inactive"},
		},
	}

	const want = "" +
		"Host: demo (ubuntu)\n" +
		"Proxy: nginx\n" +
		"Runtime: docker-compose\n" +
		"UFW: active\n" +
		"Fail2ban: active\n" +
		"Observability: enabled\n" +
		"Dashboard: http://127.0.0.1:9400/\n" +
		"Dashboard credentials: /var/lib/resistack/observability/grafana-admin.txt\n" +
		"Last snapshot: 2026-04-18T12:00:00Z\n" +
		"Observability services: snapshot=active timer=active grafana=active loki=active alloy=active\n" +
		"Security posture: critical\n" +
		"Findings: critical=1 high=2 medium=3 low=4\n" +
		"Containers:\n" +
		"- api (running, restarts=1)\n" +
		"Top findings:\n" +
		"- [critical] docker api exposed\n" +
		"- [high] fail2ban inactive\n"

	if got := formatStatus(snapshot, report); got != want {
		t.Fatalf("unexpected status output:\n%s", got)
	}
}
