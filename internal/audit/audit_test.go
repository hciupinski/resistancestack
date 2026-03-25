package audit

import (
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

func TestEvaluate_FindsHostAndCIRisks(t *testing.T) {
	cfg := config.Default("demo")
	snapshot := inventory.Snapshot{
		UFW:              inventory.ServiceState{Enabled: false, Status: "inactive"},
		Fail2ban:         inventory.ServiceState{Enabled: false, Status: "inactive"},
		SSHUsers:         []string{"root", "deployer"},
		PasswordlessSudo: false,
		Observability:    inventory.ObservabilityInfo{Enabled: false, Status: "disabled"},
		Repo: inventory.RepoInfo{
			GitHubWorkflows: []string{".github/workflows/deploy.yml"},
		},
	}

	report := Evaluate(cfg, snapshot)
	if len(report.Findings) < 4 {
		t.Fatalf("expected multiple findings, got %d", len(report.Findings))
	}
	if report.Summary.TopSeverity != config.SeverityHigh {
		t.Fatalf("expected top severity high, got %s", report.Summary.TopSeverity)
	}
}

func TestEvaluate_FindsMissingPasswordlessSudo(t *testing.T) {
	cfg := config.Default("demo")
	snapshot := inventory.Snapshot{
		PasswordlessSudo: false,
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
	}

	report := Evaluate(cfg, snapshot)
	found := false
	for _, finding := range report.Findings {
		if finding.ID == "host.sudo.passwordless-missing" {
			found = true
			if finding.AutoRemediable {
				t.Fatal("expected passwordless sudo finding to be non-auto-remediable")
			}
		}
	}
	if !found {
		t.Fatal("expected passwordless sudo finding")
	}
}
