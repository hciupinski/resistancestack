package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

type Finding struct {
	ID             string `json:"id"`
	Module         string `json:"module"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	DetectedValue  string `json:"detected_value"`
	Risk           string `json:"risk"`
	Recommendation string `json:"recommendation"`
	AutoRemediable bool   `json:"auto_remediable"`
}

type Remediation struct {
	Module string   `json:"module"`
	Reason string   `json:"reason"`
	Steps  []string `json:"steps"`
}

type Summary struct {
	BySeverity  map[string]int `json:"by_severity"`
	TopSeverity string         `json:"top_severity"`
}

type Report struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Snapshot    inventory.Snapshot `json:"snapshot"`
	Summary     Summary            `json:"summary"`
	Findings    []Finding          `json:"findings"`
	Remediation []Remediation      `json:"remediation"`
}

var severityOrder = map[string]int{
	config.SeverityLow:      1,
	config.SeverityMedium:   2,
	config.SeverityHigh:     3,
	config.SeverityCritical: 4,
}

func Evaluate(cfg config.Config, snapshot inventory.Snapshot) Report {
	findings := []Finding{}
	add := func(f Finding) {
		if severityOrder[f.Severity] == 0 {
			f.Severity = config.SeverityLow
		}
		findings = append(findings, f)
	}

	if !snapshot.UFW.Enabled {
		add(Finding{
			ID:             "host.ufw.disabled",
			Module:         "host-hardening",
			Severity:       config.SeverityHigh,
			Description:    "UFW is not active on the host.",
			DetectedValue:  snapshot.UFW.Status,
			Risk:           "Unfiltered ingress increases exposure of SSH, container, and accidental debug ports.",
			Recommendation: "Run `resistack apply host-hardening` to enforce the baseline firewall policy.",
			AutoRemediable: true,
		})
	}
	if cfg.HostHardening.SSHHardening.RequirePasswordlessSudo && !snapshot.PasswordlessSudo {
		add(Finding{
			ID:             "host.sudo.passwordless-missing",
			Module:         "host-hardening",
			Severity:       config.SeverityHigh,
			Description:    "The configured SSH user does not have passwordless sudo.",
			DetectedValue:  cfg.Server.SSHUser,
			Risk:           "Host hardening cannot safely apply SSH, UFW, fail2ban, or package changes without non-interactive privilege escalation.",
			Recommendation: fmt.Sprintf("Grant passwordless sudo to `%s`, for example: `echo '%s ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/resistack-%s && sudo chmod 440 /etc/sudoers.d/resistack-%s`, then verify with `ssh %s@%s 'sudo -n true && echo OK'`.", cfg.Server.SSHUser, cfg.Server.SSHUser, cfg.Server.SSHUser, cfg.Server.SSHUser, cfg.Server.SSHUser, cfg.Server.Host),
			AutoRemediable: false,
		})
	}
	if snapshot.Fail2ban.Status != "active" {
		add(Finding{
			ID:             "host.fail2ban.inactive",
			Module:         "host-hardening",
			Severity:       config.SeverityHigh,
			Description:    "fail2ban is not active.",
			DetectedValue:  snapshot.Fail2ban.Status,
			Risk:           "SSH brute-force and repeated auth failures are not throttled at the host layer.",
			Recommendation: "Enable fail2ban through `resistack apply host-hardening`.",
			AutoRemediable: true,
		})
	}
	if slices.Contains(snapshot.SSHUsers, "root") && cfg.HostHardening.SSHHardening.DisableRootLogin {
		add(Finding{
			ID:             "host.ssh.root-login",
			Module:         "host-hardening",
			Severity:       config.SeverityHigh,
			Description:    "Root appears as an interactive SSH user while v2 baseline expects root login to be disabled.",
			DetectedValue:  "root",
			Risk:           "Interactive root SSH access raises blast radius and weakens operator accountability.",
			Recommendation: "Apply SSH hardening and verify that privileged access flows through named sudo users.",
			AutoRemediable: true,
		})
	}
	if hasPublicPort(snapshot.ExposedPorts, 2375) {
		add(Finding{
			ID:             "host.docker.public-api",
			Module:         "host-hardening",
			Severity:       config.SeverityCritical,
			Description:    "Docker API appears to be exposed on a public interface.",
			DetectedValue:  "tcp/2375 public",
			Risk:           "Unauthenticated Docker access can result in full host compromise.",
			Recommendation: "Close the port immediately and review docker daemon configuration before further changes.",
			AutoRemediable: false,
		})
	}
	if len(cfg.HostHardening.UFWPolicy.AdminAllowlist) == 0 {
		add(Finding{
			ID:             "host.ssh.no-allowlist",
			Module:         "host-hardening",
			Severity:       config.SeverityMedium,
			Description:    "No SSH admin allowlist is configured.",
			DetectedValue:  "empty",
			Risk:           "The baseline cannot constrain SSH exposure to known operator networks.",
			Recommendation: "Populate `host_hardening.ufw_policy.admin_allowlist` with trusted operator CIDRs.",
			AutoRemediable: false,
		})
	}
	if snapshot.Proxy.Kind == "none" && len(cfg.AppInventory.Domains) > 0 {
		add(Finding{
			ID:             "inventory.proxy.none",
			Module:         "inventory-audit",
			Severity:       config.SeverityMedium,
			Description:    "No reverse proxy was detected even though domains are configured for inventory.",
			DetectedValue:  strings.Join(cfg.AppInventory.Domains, ", "),
			Risk:           "TLS handling, logging, and ingress controls may be inconsistent or externalized without visibility.",
			Recommendation: "Confirm whether ingress is handled externally or enrich `app_inventory` paths for brownfield detection.",
			AutoRemediable: false,
		})
	}
	if len(snapshot.TLSCertificates) == 0 && len(cfg.AppInventory.Domains) > 0 {
		add(Finding{
			ID:             "inventory.tls.missing",
			Module:         "inventory-audit",
			Severity:       config.SeverityMedium,
			Description:    "No local TLS certificate inventory was detected for configured domains.",
			DetectedValue:  strings.Join(cfg.AppInventory.Domains, ", "),
			Risk:           "Certificate expiry and TLS provenance cannot be assessed from the host.",
			Recommendation: "Confirm certificate ownership or document the external TLS termination path.",
			AutoRemediable: false,
		})
	}
	if !snapshot.Observability.Enabled {
		add(Finding{
			ID:             "observability.disabled",
			Module:         "security-observability",
			Severity:       config.SeverityMedium,
			Description:    "Baseline observability is not enabled.",
			DetectedValue:  snapshot.Observability.Status,
			Risk:           "Security signals from journald, nginx, docker, fail2ban, and disk pressure are not summarized centrally.",
			Recommendation: "Run `resistack observability enable` to install the local baseline timer and snapshots.",
			AutoRemediable: true,
		})
	}
	if len(snapshot.Repo.GitHubWorkflows) == 0 {
		add(Finding{
			ID:             "ci.github.workflows.none",
			Module:         "ci-security",
			Severity:       config.SeverityMedium,
			Description:    "No GitHub Actions workflows were detected in the repository.",
			DetectedValue:  "none",
			Risk:           "The repo lacks baseline automated security scanning for dependencies, containers, SBOM, and secrets.",
			Recommendation: "Run `resistack ci generate` to add standalone security workflows.",
			AutoRemediable: true,
		})
	} else if !containsSecurityWorkflow(snapshot.Repo.GitHubWorkflows) {
		add(Finding{
			ID:             "ci.security.workflows.missing",
			Module:         "ci-security",
			Severity:       config.SeverityMedium,
			Description:    "Existing GitHub Actions workflows were found, but no resistack security workflows are present.",
			DetectedValue:  strings.Join(snapshot.Repo.GitHubWorkflows, ", "),
			Risk:           "Deploy automation may exist without parallel security-only gates and artifacts.",
			Recommendation: "Generate standalone `security-*.yml` workflows so security checks do not couple to deploy pipelines.",
			AutoRemediable: true,
		})
	}
	if len(snapshot.Repo.ComposeFiles) == 0 && len(snapshot.Repo.SystemdUnits) == 0 && len(snapshot.Containers) == 0 {
		add(Finding{
			ID:             "inventory.runtime.unknown",
			Module:         "inventory-audit",
			Severity:       config.SeverityLow,
			Description:    "Application runtime could not be classified from repo or host evidence.",
			DetectedValue:  snapshot.Runtime.Kind,
			Risk:           "Later remediation steps may require manual confirmation for brownfield systems.",
			Recommendation: "Enrich `app_inventory.compose_paths` or `app_inventory.systemd_units` to improve runtime detection.",
			AutoRemediable: false,
		})
	}

	summary := Summary{BySeverity: map[string]int{}}
	for _, severity := range []string{config.SeverityCritical, config.SeverityHigh, config.SeverityMedium, config.SeverityLow} {
		summary.BySeverity[severity] = 0
	}
	topSeverity := config.SeverityLow
	for _, finding := range findings {
		summary.BySeverity[finding.Severity]++
		if severityOrder[finding.Severity] > severityOrder[topSeverity] {
			topSeverity = finding.Severity
		}
	}
	summary.TopSeverity = topSeverity

	return Report{
		GeneratedAt: time.Now().UTC(),
		Snapshot:    snapshot,
		Summary:     summary,
		Findings:    findings,
		Remediation: buildRemediation(findings),
	}
}

func Save(root string, cfg config.Config, report Report) (string, error) {
	dir := cfg.Reporting.OutputPath
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}
	format := strings.ToLower(strings.TrimSpace(cfg.Reporting.Format))
	name := "audit-report.txt"
	content := []byte(FormatText(report))
	if format == config.FormatJSON {
		name = "audit-report.json"
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal audit report: %w", err)
		}
		content = raw
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return "", fmt.Errorf("write audit report: %w", err)
	}
	return path, nil
}

func FormatText(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Audit generated at: %s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Top severity: %s\n", report.Summary.TopSeverity)
	for _, severity := range []string{config.SeverityCritical, config.SeverityHigh, config.SeverityMedium, config.SeverityLow} {
		fmt.Fprintf(&b, "%s: %d\n", severity, report.Summary.BySeverity[severity])
	}
	if len(report.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	b.WriteString("\nFindings:\n")
	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "- [%s] %s (%s)\n", strings.ToUpper(finding.Severity), finding.Description, finding.Module)
		fmt.Fprintf(&b, "  detected: %s\n", finding.DetectedValue)
		fmt.Fprintf(&b, "  risk: %s\n", finding.Risk)
		fmt.Fprintf(&b, "  recommendation: %s\n", finding.Recommendation)
		fmt.Fprintf(&b, "  auto-remediable: %t\n", finding.AutoRemediable)
	}
	if len(report.Remediation) > 0 {
		b.WriteString("\nRemediation plan:\n")
		for _, item := range report.Remediation {
			fmt.Fprintf(&b, "- %s: %s\n", item.Module, item.Reason)
			for _, step := range item.Steps {
				fmt.Fprintf(&b, "  - %s\n", step)
			}
		}
	}
	return b.String()
}

func buildRemediation(findings []Finding) []Remediation {
	moduleReasons := map[string][]Finding{}
	for _, finding := range findings {
		if !finding.AutoRemediable {
			continue
		}
		moduleReasons[finding.Module] = append(moduleReasons[finding.Module], finding)
	}

	modules := mapKeys(moduleReasons)
	slices.Sort(modules)
	remediation := make([]Remediation, 0, len(modules))
	for _, module := range modules {
		items := moduleReasons[module]
		steps := []string{}
		for _, item := range items {
			steps = append(steps, item.Recommendation)
		}
		remediation = append(remediation, Remediation{
			Module: module,
			Reason: fmt.Sprintf("%d auto-remediable finding(s)", len(items)),
			Steps:  steps,
		})
	}
	return remediation
}

func mapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

func hasPublicPort(ports []inventory.PortInfo, target int) bool {
	for _, port := range ports {
		if port.Port == target && port.Public {
			return true
		}
	}
	return false
}

func containsSecurityWorkflow(workflows []string) bool {
	for _, workflow := range workflows {
		base := filepath.Base(workflow)
		if strings.HasPrefix(base, "security-") {
			return true
		}
	}
	return false
}
