package audit

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
	"github.com/hciupinski/resistancestack/internal/netutil"
)

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
	operatorAccessMode := cfg.HostHardening.UFWPolicy.OperatorAccessMode
	if operatorAccessMode == "" {
		operatorAccessMode = config.OperatorAccessModePublicHardened
	}
	if len(cfg.HostHardening.UFWPolicy.AdminAllowlist) == 0 {
		severity := config.SeverityMedium
		description := "No SSH admin allowlist is configured while public_hardened operator access is enabled."
		risk := "SSH remains publicly reachable and relies on keys, hardening, and fail2ban rather than trusted source CIDRs."
		recommendation := "Populate `host_hardening.ufw_policy.admin_allowlist` if you want to constrain SSH to known operator networks."
		if operatorAccessMode == config.OperatorAccessModeAllowlistOnly {
			severity = config.SeverityHigh
			description = "operator_access_mode=allowlist_only is configured without a static admin allowlist."
			risk = "SSH access may depend entirely on the current preserved session and will not be safely transferable to another operator or network."
			recommendation = "Populate `host_hardening.ufw_policy.admin_allowlist` with trusted operator CIDRs before relying on allowlist_only mode."
		}
		add(Finding{
			ID:             "host.ssh.no-allowlist",
			Module:         "host-hardening",
			Severity:       severity,
			Description:    description,
			DetectedValue:  "empty",
			Risk:           risk,
			Recommendation: recommendation,
			AutoRemediable: false,
		})
	}
	if operatorAccessMode == config.OperatorAccessModeAllowlistOnly && snapshot.CurrentSessionIP != "" && !netutil.IPInAllowlist(snapshot.CurrentSessionIP, cfg.HostHardening.UFWPolicy.AdminAllowlist) {
		add(Finding{
			ID:             "host.ssh.current-session-not-allowlisted",
			Module:         "host-hardening",
			Severity:       config.SeverityHigh,
			Description:    "The current SSH operator session is outside the configured static admin allowlist.",
			DetectedValue:  snapshot.CurrentSessionIP,
			Risk:           "Strict allowlist mode may strand operators when their current source IP is not represented in the static policy.",
			Recommendation: "Add the operator's current source IP or a stable admin CIDR to `host_hardening.ufw_policy.admin_allowlist`, or switch to `public_hardened` mode.",
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
	primaryDomain := cfg.PrimaryDomain()
	if cfg.HostHardening.SSLCertificates.Enabled && primaryDomain != "" {
		matchedCert, status := inventory.LookupCertificateForDomain(snapshot.TLSCertificates, primaryDomain)
		if status != inventory.TLSCertificateStatusValid {
			detectedValue := "missing"
			description := "No valid local TLS certificate was detected for the primary managed domain."
			recommendation := fmt.Sprintf("Provision a valid local certificate for `%s` or disable `host_hardening.ssl_certificates.enabled` if TLS terminates externally.", primaryDomain)
			if cfg.HostHardening.SSLCertificates.AutoIssue {
				recommendation = fmt.Sprintf("Run `resistack apply host-hardening` to issue a Let's Encrypt certificate for `%s`.", primaryDomain)
			}
			if status == inventory.TLSCertificateStatusInvalid {
				detectedValue = fmt.Sprintf("expired or invalid: %s", matchedCert.ExpiresAt)
				description = "The primary managed domain has a local TLS certificate, but it is expired or invalid."
			}
			add(Finding{
				ID:             "inventory.tls.primary-domain.invalid",
				Module:         "inventory-audit",
				Severity:       config.SeverityMedium,
				Description:    description,
				DetectedValue:  detectedValue,
				Risk:           "TLS availability for the primary domain depends on a certificate that is missing, expired, or otherwise invalid on the VPS.",
				Recommendation: recommendation,
				AutoRemediable: cfg.HostHardening.SSLCertificates.AutoIssue,
			})
		}
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
