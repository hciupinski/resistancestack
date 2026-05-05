package audit

import (
	"strings"
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
	if report.Summary.SecurityScore < 0 || report.Summary.SecurityScore > 100 {
		t.Fatalf("expected security score in 0-100 range, got %d", report.Summary.SecurityScore)
	}
}

func TestEvaluate_LocalSnapshotReportsNotCheckedInsteadOfHostFindings(t *testing.T) {
	cfg := config.Default("demo")
	snapshot := inventory.Snapshot{
		Areas: inventory.Areas{
			Repo:          inventory.AreaStatus{Status: inventory.AreaStatusChecked},
			Host:          inventory.AreaStatus{Status: inventory.AreaStatusNotChecked, Reason: "local mode"},
			CloudExternal: inventory.AreaStatus{Status: inventory.AreaStatusNotChecked, Reason: "local mode"},
		},
		Repo: inventory.RepoInfo{
			GitHubWorkflows: []string{".github/workflows/deploy.yml"},
		},
	}

	report := Evaluate(cfg, snapshot)

	foundHostNotChecked := false
	foundCloudNotChecked := false
	for _, finding := range report.Findings {
		switch finding.ID {
		case "host.not_checked":
			foundHostNotChecked = true
			if finding.Severity != config.SeverityNotChecked {
				t.Fatalf("expected host not_checked severity, got %s", finding.Severity)
			}
		case "cloud_external.not_checked":
			foundCloudNotChecked = true
			if finding.Severity != config.SeverityNotChecked {
				t.Fatalf("expected cloud not_checked severity, got %s", finding.Severity)
			}
		case "host.ufw.disabled", "host.fail2ban.inactive", "host.sudo.passwordless-missing":
			t.Fatalf("expected local snapshot not to emit remote host finding %q", finding.ID)
		}
	}
	if !foundHostNotChecked {
		t.Fatal("expected host.not_checked finding")
	}
	if !foundCloudNotChecked {
		t.Fatal("expected cloud_external.not_checked finding")
	}
	if report.Summary.BySeverity[config.SeverityNotChecked] != 2 {
		t.Fatalf("expected two not_checked findings, got %d", report.Summary.BySeverity[config.SeverityNotChecked])
	}
}

func TestEvaluate_DockerComposeProfileFindsMissingComposeEvidence(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Deployment.Profile = config.DeploymentProfileDockerCompose
	cfg.AppInventory.ComposePaths = nil

	report := Evaluate(cfg, inventory.Snapshot{
		Areas: inventory.Areas{
			Repo: inventory.AreaStatus{Status: inventory.AreaStatusChecked},
			Host: inventory.AreaStatus{Status: inventory.AreaStatusChecked},
		},
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
		TLSCertificates:  []inventory.TLSCertificate{{Path: "/etc/letsencrypt/live/app.example.com/fullchain.pem", Names: []string{"app.example.com"}, Valid: true}},
	})

	found := false
	for _, finding := range report.Findings {
		if finding.ID == "deployment.docker-compose.compose-missing" {
			found = true
			if !strings.Contains(finding.DetectedValue, "profile=docker-compose") {
				t.Fatalf("expected profile in detected value, got %q", finding.DetectedValue)
			}
			if !strings.Contains(finding.DetectedValue, "repo:checked") {
				t.Fatalf("expected checked areas in detected value, got %q", finding.DetectedValue)
			}
		}
	}
	if !found {
		t.Fatal("expected docker-compose profile finding")
	}
}

func TestEvaluate_NodeProfileFindsMissingNodeProject(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Deployment.Profile = config.DeploymentProfileNode

	report := Evaluate(cfg, inventory.Snapshot{
		Areas: inventory.Areas{
			Repo: inventory.AreaStatus{Status: inventory.AreaStatusChecked},
			Host: inventory.AreaStatus{Status: inventory.AreaStatusNotChecked, Reason: "local mode"},
		},
		Repo: inventory.RepoInfo{
			GitHubWorkflows: []string{".github/workflows/security-dependencies.yml"},
		},
	})

	found := false
	for _, finding := range report.Findings {
		if finding.ID == "deployment.node.project-missing" {
			found = true
			if finding.Severity != config.SeverityLow {
				t.Fatalf("expected low severity, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected node profile finding")
	}
}

func TestEvaluate_ReverseProxyProfileFindsMissingProxy(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Deployment.Profile = config.DeploymentProfileReverseProxy

	report := Evaluate(cfg, inventory.Snapshot{
		Areas: inventory.Areas{
			Repo: inventory.AreaStatus{Status: inventory.AreaStatusChecked},
			Host: inventory.AreaStatus{Status: inventory.AreaStatusChecked},
		},
		Proxy:            inventory.ProxyInfo{Kind: "none"},
		UFW:              inventory.ServiceState{Enabled: true, Status: "active"},
		Fail2ban:         inventory.ServiceState{Enabled: true, Status: "active"},
		PasswordlessSudo: true,
		Observability:    inventory.ObservabilityInfo{Enabled: true, Status: "active"},
		TLSCertificates:  []inventory.TLSCertificate{{Path: "/etc/letsencrypt/live/app.example.com/fullchain.pem", Names: []string{"app.example.com"}, Valid: true}},
	})

	found := false
	for _, finding := range report.Findings {
		if finding.ID == "deployment.reverse-proxy.not-detected" {
			found = true
			if !strings.Contains(finding.Recommendation, "profile") {
				t.Fatalf("expected profile recommendation, got %q", finding.Recommendation)
			}
		}
	}
	if !found {
		t.Fatal("expected reverse-proxy profile finding")
	}
}

func TestSecurityScore_WeightsFindingsAndCapsAtZero(t *testing.T) {
	score := SecurityScore(Summary{BySeverity: map[string]int{
		config.SeverityCritical:   1,
		config.SeverityHigh:       1,
		config.SeverityMedium:     1,
		config.SeverityLow:        1,
		config.SeverityNotChecked: 1,
	}})
	if score != 41 {
		t.Fatalf("unexpected score %d", score)
	}

	score = SecurityScore(Summary{BySeverity: map[string]int{
		config.SeverityCritical: 4,
	}})
	if score != 0 {
		t.Fatalf("expected score to be capped at zero, got %d", score)
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
