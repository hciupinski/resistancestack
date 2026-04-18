package observability

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
)

const (
	grafanaVersion = "13.0.0"
	grafanaBuild   = "24384745231"
	lokiVersion    = "3.5.9"
	alloyVersion   = "1.12.1"
	lokiUID        = "resistack-loki"
)

type observabilityPaths struct {
	dataDir            string
	binDir             string
	configDir          string
	logDir             string
	downloadDir        string
	grafanaHome        string
	grafanaData        string
	grafanaLogs        string
	grafanaConfig      string
	grafanaDashboards  string
	grafanaProvision   string
	grafanaCreds       string
	lokiData           string
	lokiConfig         string
	alloyData          string
	alloyConfig        string
	snapshotLatest     string
	snapshotGlob       string
	securityGlob       string
	observeBinary      string
}

func buildPaths(dataDir string) observabilityPaths {
	return observabilityPaths{
		dataDir:           dataDir,
		binDir:            path.Join(dataDir, "bin"),
		configDir:         path.Join(dataDir, "config"),
		logDir:            path.Join(dataDir, "logs"),
		downloadDir:       path.Join(dataDir, "downloads"),
		grafanaHome:       path.Join(dataDir, "grafana-home"),
		grafanaData:       path.Join(dataDir, "grafana-data"),
		grafanaLogs:       path.Join(dataDir, "grafana-logs"),
		grafanaConfig:     path.Join(dataDir, "config", "grafana", "grafana.ini"),
		grafanaDashboards: path.Join(dataDir, "config", "grafana", "dashboards"),
		grafanaProvision:  path.Join(dataDir, "config", "grafana", "provisioning"),
		grafanaCreds:      path.Join(dataDir, "grafana-admin.txt"),
		lokiData:          path.Join(dataDir, "loki-data"),
		lokiConfig:        path.Join(dataDir, "config", "loki", "config.yaml"),
		alloyData:         path.Join(dataDir, "alloy-data"),
		alloyConfig:       path.Join(dataDir, "config", "alloy", "config.alloy"),
		snapshotLatest:    path.Join(dataDir, "latest.json"),
		snapshotGlob:      path.Join(dataDir, "logs", "snapshot-*.ndjson"),
		securityGlob:      path.Join(dataDir, "logs", "security-*.ndjson"),
		observeBinary:     "/usr/local/bin/resistack-observe",
	}
}

func buildEnvFile(cfg config.Config, paths observabilityPaths, host string, port string) string {
	healthchecks := mustCompactJSON(cfg.AppInventory.HealthcheckURLs)
	return fmt.Sprintf(`DATA_DIR=%s
LOG_DIR=%s
LATEST_PATH=%s
SNAPSHOT_GLOB=%s
SECURITY_GLOB=%s
GRAFANA_CREDENTIALS_FILE=%s
PANEL_HOST=%s
PANEL_PORT=%s
WEBHOOK_URL=%s
SLACK_URL=%s
HOST_METRICS=%t
HEALTHCHECK_URLS=%s
SSH_THRESHOLD=%d
BAN_THRESHOLD=%d
NGINX_THRESHOLD=%d
CONTAINER_RESTART_THRESHOLD=%d
DISK_THRESHOLD=%d
CERT_THRESHOLD=%d
RETENTION_DAYS=%d
`,
		quoteEnv(paths.dataDir),
		quoteEnv(paths.logDir),
		quoteEnv(paths.snapshotLatest),
		quoteEnv(paths.snapshotGlob),
		quoteEnv(paths.securityGlob),
		quoteEnv(paths.grafanaCreds),
		quoteEnv(host),
		quoteEnv(port),
		quoteEnv(cfg.Alerts.WebhookURL),
		quoteEnv(cfg.Alerts.SlackURL),
		cfg.Observability.HostMetrics,
		quoteEnv(healthchecks),
		cfg.Alerts.Thresholds.SSHFailures15m,
		cfg.Alerts.Thresholds.Bans15m,
		cfg.Alerts.Thresholds.NginxErrors15m,
		cfg.Alerts.Thresholds.ContainerRestarts,
		cfg.Alerts.Thresholds.DiskPercentUsed,
		cfg.Alerts.Thresholds.CertExpiryDays,
		cfg.Observability.RetentionDays,
	)
}

func buildGrafanaConfig(paths observabilityPaths, host string, port string) string {
	return fmt.Sprintf(`[paths]
data = %s
logs = %s
plugins = %s
provisioning = %s

[server]
protocol = http
http_addr = %s
http_port = %s
serve_from_sub_path = false

[security]
admin_user = resistack
admin_password = __RESISTACK_ADMIN_PASSWORD__

[auth]
disable_login_form = false

[auth.anonymous]
enabled = false

[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false

[users]
allow_sign_up = false
default_theme = system

[log]
mode = file
`,
		paths.grafanaData,
		paths.grafanaLogs,
		path.Join(paths.grafanaData, "plugins"),
		paths.grafanaProvision,
		host,
		port,
	)
}

func buildLokiConfig(cfg config.Config, paths observabilityPaths) string {
	retentionHours := cfg.Observability.RetentionDays * 24
	return fmt.Sprintf(`auth_enabled: false

server:
  http_listen_address: 127.0.0.1
  http_listen_port: 3100
  grpc_listen_port: 0

common:
  path_prefix: %s
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
  storage:
    filesystem:
      chunks_directory: %s
      rules_directory: %s

schema_config:
  configs:
    - from: "2024-01-01"
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

limits_config:
  retention_period: %dh
  allow_structured_metadata: true
  volume_enabled: true

compactor:
  working_directory: %s
  compaction_interval: 10m
  retention_enabled: true
  delete_request_store: filesystem

analytics:
  reporting_enabled: false
`,
		paths.lokiData,
		path.Join(paths.lokiData, "chunks"),
		path.Join(paths.lokiData, "rules"),
		retentionHours,
		path.Join(paths.lokiData, "compactor"),
	)
}

func buildAlloyConfig(cfg config.Config, paths observabilityPaths) string {
	var sections []string
	sections = append(sections,
		`logging {
  level  = "info"
  format = "logfmt"
}

loki.write "local" {
  endpoint {
    url = "http://127.0.0.1:3100/loki/api/v1/push"
  }
}
`,
	)

	if containsSource(cfg.Observability.LogSources, "journald") {
		sections = append(sections, `loki.relabel "journal" {
  forward_to = [loki.write.local.receiver]

  rule {
    source_labels = ["__journal__systemd_unit"]
    regex         = "(.*)\\.service"
    target_label  = "service"
    replacement   = "$1"
  }

  rule {
    source_labels = ["__journal_syslog_identifier"]
    regex         = "(.+)"
    target_label  = "service"
    replacement   = "$1"
  }

  rule {
    target_label = "source"
    replacement  = "journald"
  }

  rule {
    target_label = "kind"
    replacement  = "event"
  }
}

loki.source.journal "systemd" {
  labels = {
    source = "journald",
    kind   = "event",
  }
  max_age    = "24h"
  forward_to = [loki.relabel.journal.receiver]
}
`)
	}

	if containsSource(cfg.Observability.LogSources, "docker") {
		sections = append(sections, `discovery.docker "containers" {
  host = "unix:///var/run/docker.sock"
}

discovery.relabel "docker_logs" {
  targets = []

  rule {
    source_labels = ["__meta_docker_container_name"]
    regex         = "/(.*)"
    target_label  = "service"
  }

  rule {
    target_label = "source"
    replacement  = "docker"
  }

  rule {
    target_label = "kind"
    replacement  = "event"
  }
}

loki.source.docker "containers" {
  host          = "unix:///var/run/docker.sock"
  targets       = discovery.docker.containers.targets
  labels        = {source = "docker", kind = "event"}
  relabel_rules = discovery.relabel.docker_logs.rules
  forward_to    = [loki.write.local.receiver]
}
`)
	}

	fileTargets := []string{
		buildFileSourceBlock(
			"resistack_snapshot",
			paths.snapshotGlob,
			"resistack_snapshot",
			"resistack",
			"snapshot",
		),
		buildFileSourceBlock(
			"resistack_security",
			paths.securityGlob,
			"resistack_snapshot",
			"resistack",
			"security",
		),
	}

	if containsSource(cfg.Observability.LogSources, "nginx") {
		fileTargets = append(
			fileTargets,
			buildFileSourceBlock("nginx_access", "/var/log/nginx/access.log", "nginx", "nginx", "access"),
			buildFileSourceBlock("nginx_error", "/var/log/nginx/error.log", "nginx", "nginx", "error"),
		)
	}

	if containsSource(cfg.Observability.LogSources, "fail2ban") {
		fileTargets = append(
			fileTargets,
			buildFileSourceBlock("fail2ban", "/var/log/fail2ban.log", "fail2ban", "fail2ban", "security"),
		)
	}

	sections = append(sections, strings.Join(fileTargets, "\n"))
	return strings.Join(sections, "\n")
}

func buildFileSourceBlock(label string, logPath string, source string, service string, kind string) string {
	return fmt.Sprintf(`loki.source.file %q {
  targets = [{
    __path__ = %q,
    source   = %q,
    service  = %q,
    kind     = %q,
  }]
  forward_to = [loki.write.local.receiver]

  file_match {
    enabled     = true
    sync_period = "30s"
  }
}
`, label, logPath, source, service, kind)
}

func buildDatasourcesProvisioning() string {
	return `apiVersion: 1
datasources:
  - name: Loki
    uid: resistack-loki
    type: loki
    access: proxy
    url: http://127.0.0.1:3100
    isDefault: true
    editable: false
    jsonData:
      maxLines: 1000
`
}

func buildDashboardProvider(paths observabilityPaths) string {
	return fmt.Sprintf(`apiVersion: 1
providers:
  - name: Resistack
    orgId: 1
    folder: Resistack
    type: file
    disableDeletion: false
    editable: false
    updateIntervalSeconds: 30
    options:
      path: %s
`, paths.grafanaDashboards)
}

func buildDashboards() map[string]string {
	return map[string]string{
		"overview.json":       mustDashboardJSON(buildOverviewDashboard()),
		"live-logs.json":      mustDashboardJSON(buildLiveLogsDashboard()),
		"security-events.json": mustDashboardJSON(buildSecurityDashboard()),
		"blocked-ips.json":    mustDashboardJSON(buildBlockedIPsDashboard()),
		"web-activity.json":   mustDashboardJSON(buildWebActivityDashboard()),
	}
}

func buildOverviewDashboard() map[string]any {
	return dashboard(
		"resistack-overview",
		"ResistanceStack Overview",
		[]map[string]any{
			statPanel(
				1,
				"Disk Used %",
				`last_over_time({source="resistack_snapshot",kind="snapshot"} | json | event="summary" | unwrap disk_percent_used [15m])`,
				0,
				0,
				6,
				4,
			),
			statPanel(
				2,
				"SSH Failures (15m)",
				`last_over_time({source="resistack_snapshot",kind="snapshot"} | json | event="summary" | unwrap ssh_failures_15m [15m])`,
				6,
				0,
				6,
				4,
			),
			statPanel(
				3,
				"Fail2ban Bans (15m)",
				`last_over_time({source="resistack_snapshot",kind="snapshot"} | json | event="summary" | unwrap bans_15m [15m])`,
				12,
				0,
				6,
				4,
			),
			statPanel(
				4,
				"Nginx Errors (15m)",
				`last_over_time({source="resistack_snapshot",kind="snapshot"} | json | event="summary" | unwrap nginx_errors_15m [15m])`,
				18,
				0,
				6,
				4,
			),
			logsPanel(
				5,
				"Latest Snapshot Records",
				`{source="resistack_snapshot",kind="snapshot"} | json`,
				0,
				4,
				12,
				12,
			),
			logsPanel(
				6,
				"Security Snapshot Records",
				`{source="resistack_snapshot",kind="security"} | json`,
				12,
				4,
				12,
				12,
			),
		},
	)
}

func buildLiveLogsDashboard() map[string]any {
	return dashboard(
		"resistack-live-logs",
		"ResistanceStack Live Logs",
		[]map[string]any{
			logsPanel(1, "Journald", `{source="journald"}`, 0, 0, 12, 10),
			logsPanel(2, "Docker", `{source="docker"}`, 12, 0, 12, 10),
			logsPanel(3, "Nginx", `{source="nginx"}`, 0, 10, 12, 10),
			logsPanel(4, "Fail2ban", `{source="fail2ban"}`, 12, 10, 12, 10),
		},
	)
}

func buildSecurityDashboard() map[string]any {
	return dashboard(
		"resistack-security-events",
		"ResistanceStack Security Events",
		[]map[string]any{
			timeseriesPanel(
				1,
				"SSH Failures",
				`last_over_time({source="resistack_snapshot",kind="snapshot"} | json | event="summary" | unwrap ssh_failures_15m [15m])`,
				0,
				0,
				8,
				8,
			),
			timeseriesPanel(
				2,
				"Fail2ban Bans",
				`last_over_time({source="resistack_snapshot",kind="snapshot"} | json | event="summary" | unwrap bans_15m [15m])`,
				8,
				0,
				8,
				8,
			),
			statPanel(
				3,
				"Active Blocked IPs",
				`last_over_time({source="resistack_snapshot",kind="security"} | json | event="security_summary" | unwrap active_bans [15m])`,
				16,
				0,
				8,
				8,
			),
			logsPanel(
				4,
				"Recent Security Snapshot Events",
				`{source="resistack_snapshot",kind="security"} | json`,
				0,
				8,
				12,
				12,
			),
			logsPanel(
				5,
				"Fail2ban Log Stream",
				`{source="fail2ban"}`,
				12,
				8,
				12,
				12,
			),
		},
	)
}

func buildBlockedIPsDashboard() map[string]any {
	return dashboard(
		"resistack-blocked-ips",
		"ResistanceStack Blocked IPs",
		[]map[string]any{
			logsPanel(
				1,
				"Current Blocked IP Snapshot",
				`{source="resistack_snapshot",kind="security"} | json | event="blocked_ip"`,
				0,
				0,
				12,
				12,
			),
			logsPanel(
				2,
				"Alert and Ban Summary",
				`{source="resistack_snapshot",kind="security"} | json | event=~"security_summary|alert"`,
				12,
				0,
				12,
				12,
			),
		},
	)
}

func buildWebActivityDashboard() map[string]any {
	return dashboard(
		"resistack-web-activity",
		"ResistanceStack Web/API Activity",
		[]map[string]any{
			statPanel(
				1,
				"Nginx Errors (15m)",
				`last_over_time({source="resistack_snapshot",kind="snapshot"} | json | event="summary" | unwrap nginx_errors_15m [15m])`,
				0,
				0,
				6,
				4,
			),
			logsPanel(2, "Nginx Access", `{source="nginx",kind="access"}`, 0, 4, 12, 10),
			logsPanel(3, "Nginx Error", `{source="nginx",kind="error"}`, 12, 4, 12, 10),
			logsPanel(4, "Container Logs", `{source="docker"}`, 0, 14, 24, 10),
		},
	)
}

func dashboard(uid string, title string, panels []map[string]any) map[string]any {
	return map[string]any{
		"uid":           uid,
		"title":         title,
		"schemaVersion": 39,
		"version":       1,
		"refresh":       "30s",
		"timezone":      "browser",
		"editable":      false,
		"panels":        panels,
		"time": map[string]any{
			"from": "now-6h",
			"to":   "now",
		},
	}
}

func logsPanel(id int, title string, expr string, x int, y int, w int, h int) map[string]any {
	return map[string]any{
		"id":         id,
		"title":      title,
		"type":       "logs",
		"datasource": lokiDatasource(),
		"gridPos":    gridPos(x, y, w, h),
		"targets": []map[string]any{
			queryTarget("A", expr),
		},
		"options": map[string]any{
			"dedupStrategy":     "none",
			"enableLogDetails":  true,
			"prettifyLogMessage": false,
			"showLabels":        true,
			"showTime":          true,
			"sortOrder":         "Descending",
			"wrapLogMessage":    true,
		},
	}
}

func statPanel(id int, title string, expr string, x int, y int, w int, h int) map[string]any {
	return map[string]any{
		"id":         id,
		"title":      title,
		"type":       "stat",
		"datasource": lokiDatasource(),
		"gridPos":    gridPos(x, y, w, h),
		"targets": []map[string]any{
			queryTarget("A", expr),
		},
		"options": map[string]any{
			"reduceOptions": map[string]any{
				"calcs": []string{"lastNotNull"},
				"fields": "",
				"values": false,
			},
			"orientation": "auto",
			"textMode":    "auto",
		},
	}
}

func timeseriesPanel(id int, title string, expr string, x int, y int, w int, h int) map[string]any {
	return map[string]any{
		"id":         id,
		"title":      title,
		"type":       "timeseries",
		"datasource": lokiDatasource(),
		"gridPos":    gridPos(x, y, w, h),
		"targets": []map[string]any{
			queryTarget("A", expr),
		},
	}
}

func queryTarget(refID string, expr string) map[string]any {
	return map[string]any{
		"expr":      expr,
		"queryType": "range",
		"refId":     refID,
	}
}

func lokiDatasource() map[string]any {
	return map[string]any{
		"type": "loki",
		"uid":  lokiUID,
	}
}

func gridPos(x int, y int, w int, h int) map[string]any {
	return map[string]any{
		"h": h,
		"w": w,
		"x": x,
		"y": y,
	}
}

func systemdInterval(raw string) string {
	interval, err := time.ParseDuration(raw)
	if err != nil || interval <= 0 {
		return "60s"
	}
	return fmt.Sprintf("%ds", int(interval.Seconds()))
}

func containsSource(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
}

func mustDashboardJSON(v any) string {
	return mustIndentedJSON(v)
}

func mustIndentedJSON(v any) string {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func mustCompactJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func quoteEnv(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
