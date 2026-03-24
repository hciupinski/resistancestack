package audit

import (
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

func TestEvaluate_FindsHostAndCIRisks(t *testing.T) {
	cfg := config.Default("demo")
	snapshot := inventory.Snapshot{
		UFW:           inventory.ServiceState{Enabled: false, Status: "inactive"},
		Fail2ban:      inventory.ServiceState{Enabled: false, Status: "inactive"},
		SSHUsers:      []string{"root", "deployer"},
		Observability: inventory.ObservabilityInfo{Enabled: false, Status: "disabled"},
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
