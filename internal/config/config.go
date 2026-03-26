package config

import "gopkg.in/yaml.v3"

var defaultLineComments = map[string]string{
	"project_name":             "Identifier used in reports, generated files, and remote assets.",
	"mode.strategy":            "Workflow mode. Options: audit_then_apply.",
	"server.host":              "Target VPS hostname or IP.",
	"server.ssh_user":          "SSH user used by resistack to connect to the server.",
	"server.ssh_port":          "SSH port for remote access.",
	"server.private_key_path":  "Private key used for SSH authentication.",
	"server.host_key_checking": "SSH host key policy. Options: strict, accept-new.",
	"server.known_hosts_path":  "Known hosts file used when strict checking is enabled.",
	"host_hardening.enabled":   "Enable baseline host hardening.",
	"host_hardening.ssh_hardening.disable_root_login":        "Disable direct SSH login for root.",
	"host_hardening.ssh_hardening.disable_password_auth":     "Require key-based SSH authentication.",
	"host_hardening.ssh_hardening.allow_users[]":             "User explicitly allowed to log in via SSH.",
	"host_hardening.ssh_hardening.max_auth_tries":            "Maximum SSH authentication attempts per connection.",
	"host_hardening.ssh_hardening.login_grace_time_seconds":  "Seconds allowed to complete SSH login before disconnect.",
	"host_hardening.ssh_hardening.guard_current_operator":    "Protect the active operator session during hardening.",
	"host_hardening.ssh_hardening.require_passwordless_sudo": "Require non-interactive sudo for host changes.",
	"host_hardening.ufw_policy.enabled":                      "Enable UFW baseline firewall rules.",
	"host_hardening.ufw_policy.default_incoming":             "Default inbound firewall policy. Options: allow, deny, reject.",
	"host_hardening.ufw_policy.default_outgoing":             "Default outbound firewall policy. Options: allow, deny, reject.",
	"host_hardening.ufw_policy.operator_access_mode":         "SSH operator access strategy. Options: public_hardened, allowlist_only.",
	"host_hardening.ufw_policy.preserve_current_session":     "Temporarily preserve the current SSH session when needed.",
	"host_hardening.ufw_policy.allowed_tcp_ports[]":          "TCP port kept reachable on the host.",
	"host_hardening.ufw_policy.allowed_udp_ports[]":          "UDP port kept reachable on the host.",
	"host_hardening.ufw_policy.admin_allowlist[]":            "Optional static CIDR allowlist for SSH operators.",
	"host_hardening.fail2ban.enabled":                        "Enable fail2ban for SSH abuse protection.",
	"host_hardening.fail2ban.ban_time":                       "How long a source stays banned after repeated failures.",
	"host_hardening.fail2ban.find_time":                      "Window used to count repeated failures.",
	"host_hardening.fail2ban.max_retry":                      "Failed attempts allowed before a ban.",
	"host_hardening.fail2ban.recidive_enabled":               "Enable longer recidive bans for repeat offenders.",
	"host_hardening.fail2ban.recidive_ban_time":              "Ban duration for recidive offenders.",
	"host_hardening.ssl_certificates.enabled":                "Manage local TLS certificate checks for the primary app_inventory domain.",
	"host_hardening.ssl_certificates.auto_issue":             "Automatically issue a missing or expired Let's Encrypt certificate during host hardening.",
	"host_hardening.ssl_certificates.email":                  "Email address used for Let's Encrypt registration and expiry notices.",
	"host_hardening.ssl_certificates.staging":                "Use the Let's Encrypt staging environment for test issuance.",
	"host_hardening.automatic_security_updates":              "Enable automatic security updates on the host.",
	"host_hardening.check_deploy_user":                       "Verify the configured SSH user exists on the server.",
	"host_hardening.check_docker_daemon":                     "Inspect docker daemon settings for risky listeners.",
	"host_hardening.backup_dir":                              "Directory used for host-hardening backups and rollback.",
	"app_inventory.compose_paths[]":                          "Compose path hint used during repo and host inventory.",
	"app_inventory.nginx_paths[]":                            "Nginx path hint used during brownfield detection.",
	"app_inventory.systemd_units[]":                          "Systemd unit hint used during runtime detection.",
	"app_inventory.domains[]":                                "Domain hint used for ingress and TLS inventory.",
	"app_inventory.healthcheck_urls[]":                       "Optional health endpoints used by audit and observability.",
	"observability.enable":                                   "Enable local security observability baseline.",
	"observability.log_sources[]":                            "Log source collected by the observability baseline.",
	"observability.host_metrics":                             "Collect host-level runtime metrics and disk pressure.",
	"observability.panel_bind":                               "Local bind address for the observability panel.",
	"observability.local_data_dir":                           "Directory used for observability snapshots and local panel data.",
	"ci.provider":                                            "CI provider used by generated workflows. Options: github_actions.",
	"ci.generate_workflows":                                  "Generate standalone security workflows in the repo.",
	"ci.mode":                                                "Workflow enforcement mode. Options: warn-only, enforced.",
	"ci.schedule":                                            "Cron schedule for recurring security scans.",
	"ci.github.repository_visibility":                        "Repo visibility used for GitHub security features. Options: unknown, public, private, internal.",
	"ci.github.code_scanning_enabled":                        "Set true when GitHub code scanning is already enabled for this repo.",
	"ci.github.sarif_upload_mode":                            "SARIF upload strategy. Options: auto, enabled, disabled.",
	"ci.scans.dependency":                                    "Enable dependency and SCA workflow generation.",
	"ci.scans.image":                                         "Enable container and image scan workflow generation.",
	"ci.scans.sbom":                                          "Enable SBOM generation workflow.",
	"ci.scans.secrets":                                       "Enable secret scanning workflow.",
	"ci.scans.license":                                       "Enable license inventory checks in CI.",
	"ci.scans.osv":                                           "Enable OSV-based vulnerability scanning.",
	"reporting.output_path":                                  "Directory used to store generated reports.",
	"reporting.format":                                       "Report format. Options: text, json.",
	"reporting.minimum_severity":                             "Lowest severity included in generated reports. Options: low, medium, high, critical.",
	"alerts.webhook_url":                                     "Webhook endpoint for alert delivery.",
	"alerts.email":                                           "Email target used for alert routing metadata.",
	"alerts.slack_url":                                       "Slack webhook used for alert delivery.",
	"alerts.enabled":                                         "Enable alert generation for observability findings.",
	"alerts.thresholds.ssh_failures_15m":                     "SSH failures in 15 minutes required to trigger an alert.",
	"alerts.thresholds.bans_15m":                             "fail2ban bans in 15 minutes required to trigger an alert.",
	"alerts.thresholds.nginx_errors_15m":                     "Nginx 4xx and 5xx events in 15 minutes required to trigger an alert.",
	"alerts.thresholds.container_restarts":                   "Container restart count required to trigger an alert.",
	"alerts.thresholds.disk_percent_used":                    "Disk usage percentage required to trigger an alert.",
	"alerts.thresholds.cert_expiry_days":                     "Certificate days-to-expiry required to trigger an alert.",
}

func annotateDefaultComments(doc *yaml.Node) {
	if doc == nil || len(doc.Content) == 0 {
		return
	}
	annotateNode(doc.Content[0], "")
}

func annotateNode(node *yaml.Node, path string) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			childPath := keyNode.Value
			if path != "" {
				childPath = path + "." + keyNode.Value
			}
			if comment, ok := defaultLineComments[childPath]; ok {
				valueNode.LineComment = comment
			}
			annotateNode(valueNode, childPath)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if comment, ok := defaultLineComments[path+"[]"]; ok {
				child.LineComment = comment
			}
			annotateNode(child, path+"[]")
		}
	}
}

func mergeMissingDefaults(existingDoc *yaml.Node, defaultDoc *yaml.Node) []string {
	if existingDoc.Kind == yaml.DocumentNode && len(existingDoc.Content) > 0 {
		existingDoc = existingDoc.Content[0]
	}
	if defaultDoc.Kind == yaml.DocumentNode && len(defaultDoc.Content) > 0 {
		defaultDoc = defaultDoc.Content[0]
	}
	return mergeMappingNode(existingDoc, defaultDoc, "")
}

func mergeMappingNode(existing *yaml.Node, defaults *yaml.Node, path string) []string {
	if existing.Kind != yaml.MappingNode || defaults.Kind != yaml.MappingNode {
		return nil
	}

	added := []string{}
	for i := 0; i < len(defaults.Content); i += 2 {
		defaultKey := defaults.Content[i]
		defaultValue := defaults.Content[i+1]
		childPath := defaultKey.Value
		if path != "" {
			childPath = path + "." + defaultKey.Value
		}

		index := mappingIndex(existing, defaultKey.Value)
		if index == -1 {
			existing.Content = append(existing.Content, cloneNode(defaultKey), cloneNode(defaultValue))
			added = append(added, childPath)
			continue
		}

		existingValue := existing.Content[index+1]
		if existingValue.Kind == yaml.MappingNode && defaultValue.Kind == yaml.MappingNode {
			added = append(added, mergeMappingNode(existingValue, defaultValue, childPath)...)
		}
	}
	return added
}

func mappingIndex(node *yaml.Node, key string) int {
	if node.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return i
		}
	}
	return -1
}

func cloneNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	clone := *node
	clone.Content = make([]*yaml.Node, 0, len(node.Content))
	for _, child := range node.Content {
		clone.Content = append(clone.Content, cloneNode(child))
	}
	return &clone
}

func normalizeLegacy(cfg *Config) {
	if len(cfg.HostHardening.UFWPolicy.AdminAllowlist) == 0 && len(cfg.LegacySecurity.AdminAllowlist) > 0 {
		cfg.HostHardening.UFWPolicy.AdminAllowlist = append([]string{}, cfg.LegacySecurity.AdminAllowlist...)
	}
	if len(cfg.AppInventory.ComposePaths) == 0 && cfg.LegacyApp.ComposeFile != "" {
		cfg.AppInventory.ComposePaths = []string{cfg.LegacyApp.ComposeFile}
	}
	if len(cfg.AppInventory.HealthcheckURLs) == 0 && cfg.LegacyApp.HealthcheckURL != "" {
		cfg.AppInventory.HealthcheckURLs = []string{cfg.LegacyApp.HealthcheckURL}
	}
	if len(cfg.AppInventory.Domains) == 0 && cfg.LegacyDomain.FQDN != "" {
		cfg.AppInventory.Domains = []string{cfg.LegacyDomain.FQDN}
	}
}
