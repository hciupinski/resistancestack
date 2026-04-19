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

func TestEvaluate_PublicHardenedWithoutAllowlistIsNotABlocker(t *testing.T) {
	cfg := config.Default("demo")
	cfg.HostHardening.UFWPolicy.AdminAllowlist = nil
	cfg.HostHardening.UFWPolicy.OperatorAccessMode = config.OperatorAccessModePublicHardened

	report := Evaluate(cfg, inventory.Snapshot{
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
	})

	for _, finding := range report.Findings {
		if finding.ID == "host.ssh.no-allowlist" && finding.Severity != config.SeverityMedium {
			t.Fatalf("expected medium severity, got %s", finding.Severity)
		}
	}
}

func TestEvaluate_AllowlistOnlyWithoutMatchingCurrentSessionIsHighSeverity(t *testing.T) {
	cfg := config.Default("demo")
	cfg.HostHardening.UFWPolicy.AdminAllowlist = []string{"203.0.113.10/32"}
	cfg.HostHardening.UFWPolicy.OperatorAccessMode = config.OperatorAccessModeAllowlistOnly

	report := Evaluate(cfg, inventory.Snapshot{
		CurrentSessionIP: "77.236.29.238",
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
	})

	found := false
	for _, finding := range report.Findings {
		if finding.ID == "host.ssh.current-session-not-allowlisted" {
			found = true
			if finding.Severity != config.SeverityHigh {
				t.Fatalf("expected high severity, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected current-session-not-allowlisted finding")
	}
}

func TestEvaluate_ManagedPrimaryDomainWithoutValidCertFindsIssue(t *testing.T) {
	cfg := config.Default("demo")

	report := Evaluate(cfg, inventory.Snapshot{
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
	})

	found := false
	for _, finding := range report.Findings {
		if finding.ID == "inventory.tls.primary-domain.invalid" {
			found = true
			if finding.AutoRemediable {
				t.Fatal("expected finding to be non-auto-remediable when auto_issue=false")
			}
		}
	}
	if !found {
		t.Fatal("expected managed TLS finding")
	}
}

func TestEvaluate_ManagedPrimaryDomainWithValidCertSkipsIssue(t *testing.T) {
	cfg := config.Default("demo")

	report := Evaluate(cfg, inventory.Snapshot{
		TLSCertificates: []inventory.TLSCertificate{
			{Path: "/etc/letsencrypt/live/app.example.com/fullchain.pem", Names: []string{"app.example.com"}, ExpiresAt: "Jan  1 00:00:00 2030 GMT", Valid: true},
		},
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
	})

	for _, finding := range report.Findings {
		if finding.ID == "inventory.tls.primary-domain.invalid" {
			t.Fatal("expected no managed TLS finding")
		}
	}
}

func TestEvaluate_ExpiredManagedPrimaryDomainIsAutoRemediableWhenEnabled(t *testing.T) {
	cfg := config.Default("demo")
	cfg.HostHardening.SSLCertificates.AutoIssue = true

	report := Evaluate(cfg, inventory.Snapshot{
		TLSCertificates: []inventory.TLSCertificate{
			{Path: "/etc/letsencrypt/live/app.example.com-0001/fullchain.pem", Names: []string{"app.example.com"}, ExpiresAt: "Jan  1 00:00:00 2024 GMT", Valid: false},
		},
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
	})

	found := false
	for _, finding := range report.Findings {
		if finding.ID == "inventory.tls.primary-domain.invalid" {
			found = true
			if !finding.AutoRemediable {
				t.Fatal("expected finding to be auto-remediable when auto_issue=true")
			}
		}
	}
	if !found {
		t.Fatal("expected managed TLS finding for expired certificate")
	}
}

func TestEvaluate_DisabledManagedSSLSkipsPrimaryDomainFinding(t *testing.T) {
	cfg := config.Default("demo")
	cfg.HostHardening.SSLCertificates.Enabled = false

	report := Evaluate(cfg, inventory.Snapshot{
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
	})

	for _, finding := range report.Findings {
		if finding.ID == "inventory.tls.primary-domain.invalid" {
			t.Fatal("expected no managed TLS finding when ssl_certificates.enabled=false")
		}
	}
}

func TestEvaluate_FindsRootCutoffWithoutReplacement(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.SSHUser = "root"
	cfg.HostHardening.SSHHardening.AllowUsers = nil

	report := Evaluate(cfg, inventory.Snapshot{
		SSHUsers:         []string{"root"},
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
		TLSCertificates:  []inventory.TLSCertificate{{Path: "/etc/letsencrypt/live/app.example.com/fullchain.pem", Names: []string{"app.example.com"}, Valid: true}},
	})

	found := false
	for _, finding := range report.Findings {
		if finding.ID == "host.ssh.root-cutoff-without-replacement" {
			found = true
			if finding.Severity != config.SeverityHigh {
				t.Fatalf("expected high severity, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected root cutoff finding")
	}
}

func TestEvaluate_FindsMissingManagedAllowUsers(t *testing.T) {
	cfg := config.Default("demo")
	cfg.HostHardening.SSHHardening.AllowUsers = []string{"deployer", "missing-user"}

	report := Evaluate(cfg, inventory.Snapshot{
		SSHUsers:         []string{"deployer"},
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
		TLSCertificates:  []inventory.TLSCertificate{{Path: "/etc/letsencrypt/live/app.example.com/fullchain.pem", Names: []string{"app.example.com"}, Valid: true}},
	})

	found := false
	for _, finding := range report.Findings {
		if finding.ID == "host.ssh.allow-users-missing" {
			found = true
			if finding.Severity != config.SeverityMedium {
				t.Fatalf("expected medium severity, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected missing allow_users finding")
	}
}
