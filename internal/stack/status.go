package stack

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

type StatusReport struct {
	Project         string   `json:"project"`
	Host            string   `json:"host"`
	Docker          string   `json:"docker"`
	Fail2ban        string   `json:"fail2ban"`
	Nginx           string   `json:"nginx"`
	TLS             bool     `json:"tls"`
	HealthcheckCode string   `json:"healthcheck_code"`
	DashboardCode   string   `json:"dashboard_code"`
	Certificate     string   `json:"certificate"`
	SSHFail5m       int      `json:"ssh_fail_5m"`
	BansPerHour     int      `json:"bans_per_hour"`
	ProbePerHour    int      `json:"probe_per_hour"`
	Upstream5m      int      `json:"upstream_5m"`
	Containers      []string `json:"containers"`
	Fail2banStatus  string   `json:"fail2ban_status"`
}

func Status(cfg config.Config, out io.Writer) error {
	target := newTarget(cfg)
	report, err := captureStatus(target, cfg)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Project: %s\n", report.Project)
	fmt.Fprintf(out, "Host: %s\n", report.Host)
	fmt.Fprintf(out, "Docker: %s\n", report.Docker)
	fmt.Fprintf(out, "Fail2ban: %s\n", report.Fail2ban)
	fmt.Fprintf(out, "Nginx: %s\n", report.Nginx)
	fmt.Fprintf(out, "TLS enabled: %t\n", report.TLS)
	if report.HealthcheckCode != "" {
		fmt.Fprintf(out, "Healthcheck HTTP code: %s\n", report.HealthcheckCode)
	}
	if report.DashboardCode != "" {
		fmt.Fprintf(out, "Dashboard HTTP code: %s\n", report.DashboardCode)
	}
	if report.Certificate != "" {
		fmt.Fprintf(out, "Certificate: %s\n", report.Certificate)
	}

	fmt.Fprintf(out, "SSH fails (5m): %d / threshold %d\n", report.SSHFail5m, cfg.Alerts.Thresholds.SSHFail5m)
	fmt.Fprintf(out, "Fail2ban bans (1h): %d / threshold %d\n", report.BansPerHour, cfg.Alerts.Thresholds.BansPerHour)
	fmt.Fprintf(out, "HTTP probes (1h): %d / threshold %d\n", report.ProbePerHour, cfg.Alerts.Thresholds.ProbePerHour)
	fmt.Fprintf(out, "Upstream 5xx (5m): %d / threshold %d\n", report.Upstream5m, cfg.Alerts.Thresholds.Upstream5m)

	if alerts := evaluateThresholdAlerts(cfg, report); len(alerts) > 0 {
		fmt.Fprintln(out, "Alerts:")
		for _, alert := range alerts {
			fmt.Fprintf(out, "- %s\n", alert)
		}
	}

	if len(report.Containers) > 0 {
		fmt.Fprintln(out, "Containers:")
		for _, container := range report.Containers {
			fmt.Fprintln(out, container)
		}
	}
	if strings.TrimSpace(report.Fail2banStatus) != "" {
		fmt.Fprintln(out, "Fail2ban sshd status:")
		fmt.Fprintln(out, strings.TrimSpace(report.Fail2banStatus))
	}
	return nil
}

func captureStatus(target remote.Target, cfg config.Config) (StatusReport, error) {
	raw, err := remote.CaptureScript(target, buildStatusScript(cfg))
	if err != nil {
		return StatusReport{}, err
	}

	var report StatusReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return StatusReport{}, fmt.Errorf("decode status report: %w", err)
	}
	return report, nil
}

func evaluateThresholdAlerts(cfg config.Config, report StatusReport) []string {
	var alerts []string
	if report.SSHFail5m >= cfg.Alerts.Thresholds.SSHFail5m {
		alerts = append(alerts, "SSH failures exceeded configured threshold")
	}
	if report.BansPerHour >= cfg.Alerts.Thresholds.BansPerHour {
		alerts = append(alerts, "Fail2ban ban rate exceeded configured threshold")
	}
	if report.ProbePerHour >= cfg.Alerts.Thresholds.ProbePerHour {
		alerts = append(alerts, "HTTP probe rate exceeded configured threshold")
	}
	if report.Upstream5m >= cfg.Alerts.Thresholds.Upstream5m {
		alerts = append(alerts, "Upstream 5xx rate exceeded configured threshold")
	}
	return alerts
}

func buildStatusScript(cfg config.Config) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
PROJECT=%s
FQDN=%s
APP_HEALTHCHECK_URL=%s
DASHBOARD_PATH=%s
TLS_ENABLED=%s
DASHBOARD_BASIC_AUTH_ENABLED=%s
DASHBOARD_USERNAME=%s
DASHBOARD_PASSWORD=%s
export PROJECT FQDN APP_HEALTHCHECK_URL DASHBOARD_PATH TLS_ENABLED DASHBOARD_BASIC_AUTH_ENABLED DASHBOARD_USERNAME DASHBOARD_PASSWORD
python3 - <<'PY'
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone

project = os.environ["PROJECT"]
fqdn = os.environ["FQDN"]
healthcheck_url = os.environ["APP_HEALTHCHECK_URL"]
dashboard_path = os.environ["DASHBOARD_PATH"]
tls_enabled = os.environ["TLS_ENABLED"] == "true"
dashboard_auth = os.environ["DASHBOARD_BASIC_AUTH_ENABLED"] == "true"
dashboard_username = os.environ["DASHBOARD_USERNAME"]
dashboard_password = os.environ["DASHBOARD_PASSWORD"]

now = datetime.now(timezone.utc)
probe_cutoff = now - timedelta(hours=1)
upstream_cutoff = now - timedelta(minutes=5)
suspicious = re.compile(r"(wp-admin|wp-login\.php|xmlrpc\.php|phpmyadmin|\.env|\.git|boaform|cgi-bin|server-status|actuator|HNAP1|/admin|/login)", re.IGNORECASE)

def run(command):
    return subprocess.run(command, text=True, capture_output=True)

def capture_text(command):
    result = run(command)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()

def service_state(service):
    result = run(["systemctl", "is-active", service])
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip()

def http_code(command):
    result = run(command)
    return result.stdout.strip()

ssh_logs = capture_text(["bash", "-lc", "journalctl -u ssh --since '-5 minutes' --no-pager 2>/dev/null || journalctl -u sshd --since '-5 minutes' --no-pager 2>/dev/null || true"])
ssh_fail_5m = len(re.findall(r"Failed password|Invalid user", ssh_logs))

fail2ban_logs = capture_text(["bash", "-lc", "journalctl -u fail2ban --since '-1 hour' --no-pager 2>/dev/null || true"])
bans_per_hour = len(re.findall(r" Ban ", fail2ban_logs))

probe_per_hour = 0
upstream_5m = 0
access_log = "/var/log/nginx/resistack-access.log"
if os.path.exists(access_log):
    with open(access_log, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            parts = line.rstrip("\n").split("\t", 5)
            if len(parts) < 4:
                continue
            try:
                logged_at = datetime.fromisoformat(parts[0])
            except ValueError:
                continue
            status_code = int(parts[1])
            uri = parts[3]
            if logged_at >= probe_cutoff and suspicious.search(uri):
                probe_per_hour += 1
            if logged_at >= upstream_cutoff and status_code in (500, 502, 503, 504):
                upstream_5m += 1

dashboard_url = f"http://127.0.0.1{dashboard_path}"
dashboard_cmd = ["curl", "-fsS", "-o", "/dev/null", "-w", "%%{http_code}", "-H", f"Host: {fqdn}"]
if dashboard_auth:
    dashboard_cmd += ["-u", f"{dashboard_username}:{dashboard_password}"]
dashboard_cmd.append(dashboard_url)
if tls_enabled:
    dashboard_cmd = ["curl", "-ksS", "-o", "/dev/null", "-w", "%%{http_code}", "--resolve", f"{fqdn}:443:127.0.0.1"]
    if dashboard_auth:
        dashboard_cmd += ["-u", f"{dashboard_username}:{dashboard_password}"]
    dashboard_cmd.append(f"https://{fqdn}{dashboard_path}")

report = {
    "project": project,
    "host": capture_text(["hostname"]),
    "docker": service_state("docker"),
    "fail2ban": service_state("fail2ban"),
    "nginx": service_state("nginx"),
    "tls": tls_enabled,
    "healthcheck_code": http_code(["bash", "-lc", f"curl -fsS -o /dev/null -w '%%{{http_code}}' {healthcheck_url!r} || true"]),
    "dashboard_code": http_code(dashboard_cmd),
    "certificate": capture_text(["bash", "-lc", f"cert=/etc/letsencrypt/live/{fqdn}/fullchain.pem; if [ -f \"$cert\" ]; then openssl x509 -in \"$cert\" -noout -enddate; fi"]),
    "ssh_fail_5m": ssh_fail_5m,
    "bans_per_hour": bans_per_hour,
    "probe_per_hour": probe_per_hour,
    "upstream_5m": upstream_5m,
    "containers": [line for line in capture_text(["bash", "-lc", "sudo docker ps --format '{{.Names}}\\t{{.Status}}' 2>/dev/null || true"]).splitlines() if line],
    "fail2ban_status": capture_text(["bash", "-lc", "sudo fail2ban-client status sshd 2>/dev/null || true"]),
}
print(json.dumps(report))
PY
`, shellQuote(cfg.ProjectName),
		shellQuote(cfg.Domain.FQDN),
		shellQuote(cfg.App.HealthcheckURL),
		shellQuote(cfg.Dashboard.Path),
		shellQuote(boolString(cfg.TLS.Enabled)),
		shellQuote(boolString(cfg.Dashboard.BasicAuth.Enabled)),
		shellQuote(cfg.Dashboard.BasicAuth.Username),
		shellQuote(cfg.Dashboard.BasicAuth.Password))
}
