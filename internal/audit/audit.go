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
		if _, ok := severityOrder[f.Severity]; !ok {
			f.Severity = config.SeverityLow
		}
		findings = append(findings, f)
	}

	managedSSHUsers := config.ManagedSSHAllowUsers(cfg)
	futureSSHUsers := config.FutureSSHLoginUsers(cfg)
	hostChecked := snapshot.Areas.Host.Status != inventory.AreaStatusNotChecked
	cloudExternalChecked := snapshot.Areas.CloudExternal.Status != inventory.AreaStatusNotChecked

	if !hostChecked {
		reason := strings.TrimSpace(snapshot.Areas.Host.Reason)
		if reason == "" {
			reason = "host inventory was not collected"
		}
		add(Finding{
			ID:             "host.not_checked",
			Module:         "host-hardening",
			Severity:       config.SeverityNotChecked,
			Description:    "Host hardening checks were not executed.",
			DetectedValue:  reason,
			Risk:           "SSH, sudo, firewall, fail2ban, exposed ports, TLS files, and host services are outside this local audit snapshot.",
			Recommendation: "Run `resistack inventory` or `resistack audit` without `--local` after SSH access is configured.",
			AutoRemediable: false,
		})
	} else if !snapshot.UFW.Enabled {
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
	if hostChecked && cfg.HostHardening.SSHHardening.RequirePasswordlessSudo && !snapshot.PasswordlessSudo {
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
	if hostChecked && snapshot.Fail2ban.Status != "active" {
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
	if hostChecked && slices.Contains(snapshot.SSHUsers, "root") && cfg.HostHardening.SSHHardening.DisableRootLogin {
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
	if hostChecked && cfg.Server.SSHUser != "" && !slices.Contains(futureSSHUsers, cfg.Server.SSHUser) {
		add(Finding{
			ID:             "host.ssh.configured-user-cutoff",
			Module:         "host-hardening",
			Severity:       config.SeverityMedium,
			Description:    "The configured server.ssh_user will not remain usable after SSH hardening.",
			DetectedValue:  cfg.Server.SSHUser,
			Risk:           "Future Resistack runs can fail after hardening because the configured SSH identity will be excluded or disabled.",
			Recommendation: "Update `server.ssh_user` to a verified future SSH user before or immediately after host hardening.",
			AutoRemediable: false,
		})
	}
	if hostChecked && cfg.Server.SSHUser == "root" && cfg.HostHardening.SSHHardening.DisableRootLogin && len(futureSSHUsers) == 0 {
		add(Finding{
			ID:             "host.ssh.root-cutoff-without-replacement",
			Module:         "host-hardening",
			Severity:       config.SeverityHigh,
			Description:    "Root login is configured to be disabled without an explicit non-root SSH replacement.",
			DetectedValue:  "root",
			Risk:           "Applying SSH hardening from a root session can remove the only declared login path.",
			Recommendation: "Bootstrap a named SSH user with authorized_keys, add it to `host_hardening.ssh_hardening.allow_users`, and switch `server.ssh_user` to that account.",
			AutoRemediable: false,
		})
	}
	if hostChecked && len(managedSSHUsers) > 0 {
		missingManagedSSHUsers := []string{}
		presentFutureSSHUsers := 0
		for _, user := range managedSSHUsers {
			if cfg.HostHardening.SSHHardening.DisableRootLogin && user == "root" {
				continue
			}
			if slices.Contains(snapshot.SSHUsers, user) {
				presentFutureSSHUsers++
				continue
			}
			missingManagedSSHUsers = append(missingManagedSSHUsers, user)
		}
		if len(missingManagedSSHUsers) > 0 {
			severity := config.SeverityMedium
			risk := "The managed AllowUsers policy references accounts that were not detected as interactive SSH users."
			recommendation := "Verify these accounts exist, have a real login shell, and have authorized_keys before host hardening."
			if presentFutureSSHUsers == 0 {
				severity = config.SeverityHigh
				risk = "Applying the managed AllowUsers policy can remove every declared non-root SSH path."
				recommendation = "Create and verify at least one non-root SSH user in `host_hardening.ssh_hardening.allow_users` before host hardening."
			}
			add(Finding{
				ID:             "host.ssh.allow-users-missing",
				Module:         "host-hardening",
				Severity:       severity,
				Description:    "Some managed AllowUsers accounts were not detected on the host.",
				DetectedValue:  strings.Join(missingManagedSSHUsers, ", "),
				Risk:           risk,
				Recommendation: recommendation,
				AutoRemediable: false,
			})
		}
	}
	if hostChecked && hasPublicPort(snapshot.ExposedPorts, 2375) {
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
	if hostChecked && operatorAccessMode == config.OperatorAccessModeAllowlistOnly && snapshot.CurrentSessionIP != "" && !netutil.IPInAllowlist(snapshot.CurrentSessionIP, cfg.HostHardening.UFWPolicy.AdminAllowlist) {
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
	if hostChecked && snapshot.Proxy.Kind == "none" && len(cfg.AppInventory.Domains) > 0 {
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
	if hostChecked && cfg.HostHardening.SSLCertificates.Enabled && primaryDomain != "" {
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
	if hostChecked && !snapshot.Observability.Enabled {
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
	if !cloudExternalChecked {
		reason := strings.TrimSpace(snapshot.Areas.CloudExternal.Reason)
		if reason == "" {
			reason = "cloud and external services were not collected"
		}
		add(Finding{
			ID:             "cloud_external.not_checked",
			Module:         "cloud-external",
			Severity:       config.SeverityNotChecked,
			Description:    "Cloud and external dependency checks were not executed.",
			DetectedValue:  reason,
			Risk:           "DNS, CDN/WAF, cloud firewall, provider backups, and external TLS termination may affect security posture but are not represented in this report.",
			Recommendation: "Add provider-specific checks in a remote or cloud-aware audit workflow.",
			AutoRemediable: false,
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
	for _, severity := range []string{config.SeverityCritical, config.SeverityHigh, config.SeverityMedium, config.SeverityLow, config.SeverityNotChecked} {
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
