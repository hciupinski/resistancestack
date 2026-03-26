package observability

import (
	"fmt"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/scriptutil"
)

func BuildEnableScript(cfg config.Config) string {
	host, port := splitBind(cfg.Observability.PanelBind)
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
DATA_DIR=%s
PANEL_HOST=%s
PANEL_PORT=%s
WEBHOOK_URL=%s
SLACK_URL=%s
SSH_THRESHOLD=%d
BAN_THRESHOLD=%d
NGINX_THRESHOLD=%d
CONTAINER_RESTART_THRESHOLD=%d
DISK_THRESHOLD=%d
CERT_THRESHOLD=%d

sudo install -d -m 0755 "${DATA_DIR}"

cat > /tmp/resistack-observe <<'PY'
#!/usr/bin/env python3
import glob
import json
import os
import re
import subprocess
import urllib.request
from datetime import datetime, timezone

DATA_DIR = os.environ["DATA_DIR"]
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
SLACK_URL = os.environ.get("SLACK_URL", "")
SSH_THRESHOLD = int(os.environ["SSH_THRESHOLD"])
BAN_THRESHOLD = int(os.environ["BAN_THRESHOLD"])
NGINX_THRESHOLD = int(os.environ["NGINX_THRESHOLD"])
CONTAINER_RESTART_THRESHOLD = int(os.environ["CONTAINER_RESTART_THRESHOLD"])
DISK_THRESHOLD = int(os.environ["DISK_THRESHOLD"])
CERT_THRESHOLD = int(os.environ["CERT_THRESHOLD"])

def text(command):
    result = subprocess.run(command, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else ""

ssh_logs = text(["bash", "-lc", "journalctl -u ssh --since '-15 minutes' --no-pager 2>/dev/null || journalctl -u sshd --since '-15 minutes' --no-pager 2>/dev/null || true"])
fail2ban_logs = text(["bash", "-lc", "journalctl -u fail2ban --since '-15 minutes' --no-pager 2>/dev/null || true"])
nginx_logs = text(["bash", "-lc", "tail -n 400 /var/log/nginx/access.log 2>/dev/null || true"])
nginx_errors = 0
for line in nginx_logs.splitlines():
    match = re.search(r'"\s([45]\d\d)\s', line)
    if match:
        nginx_errors += 1

containers = []
docker_ids = text(["bash", "-lc", "sudo docker ps -q 2>/dev/null || true"]).splitlines()
for container_id in docker_ids:
    inspect = text(["bash", "-lc", f"sudo docker inspect {container_id} 2>/dev/null"])
    if not inspect:
        continue
    data = json.loads(inspect)[0]
    containers.append({
        "name": data.get("Name", "").lstrip("/"),
        "status": data.get("State", {}).get("Status", ""),
        "restarts": data.get("RestartCount", 0),
    })

certificates = []
for fullchain in glob.glob("/etc/letsencrypt/live/*/fullchain.pem"):
    expiry = text(["bash", "-lc", f"openssl x509 -in {fullchain!r} -noout -enddate 2>/dev/null | cut -d= -f2-"])
    certificates.append({"path": fullchain, "expires_at": expiry})

disk_output = text(["bash", "-lc", "df -P / | tail -n 1 | awk '{print $5}' | tr -d '%%'"])
disk_percent = int(disk_output) if disk_output.isdigit() else 0

payload = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "ssh_failures_15m": len(re.findall(r"Failed password|Invalid user", ssh_logs)),
    "bans_15m": len(re.findall(r" Ban ", fail2ban_logs)),
    "nginx_errors_15m": nginx_errors,
    "containers": containers,
    "disk_percent_used": disk_percent,
    "certificates": certificates,
}

with open(os.path.join(DATA_DIR, "latest.json"), "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)

alerts = []
if payload["ssh_failures_15m"] >= SSH_THRESHOLD:
    alerts.append("ssh_bruteforce")
if payload["bans_15m"] >= BAN_THRESHOLD:
    alerts.append("ban_burst")
if payload["nginx_errors_15m"] >= NGINX_THRESHOLD:
    alerts.append("nginx_4xx_5xx_anomaly")
if any(item["restarts"] >= CONTAINER_RESTART_THRESHOLD for item in containers):
    alerts.append("container_restarts")
if disk_percent >= DISK_THRESHOLD:
    alerts.append("disk_pressure")
if certificates:
    for cert in certificates:
        if cert["expires_at"]:
            alerts.append("certificates_present")
            break

if alerts:
    outgoing = json.dumps({"alerts": alerts, "snapshot": payload}).encode("utf-8")
    for endpoint in (WEBHOOK_URL, SLACK_URL):
        if not endpoint:
            continue
        try:
            req = urllib.request.Request(endpoint, data=outgoing, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).read()
        except Exception:
            pass
PY
sudo mv /tmp/resistack-observe /usr/local/bin/resistack-observe
sudo chmod 0755 /usr/local/bin/resistack-observe

cat > /tmp/resistack-observability.env <<EOF
DATA_DIR=${DATA_DIR}
WEBHOOK_URL=${WEBHOOK_URL}
SLACK_URL=${SLACK_URL}
SSH_THRESHOLD=${SSH_THRESHOLD}
BAN_THRESHOLD=${BAN_THRESHOLD}
NGINX_THRESHOLD=${NGINX_THRESHOLD}
CONTAINER_RESTART_THRESHOLD=${CONTAINER_RESTART_THRESHOLD}
DISK_THRESHOLD=${DISK_THRESHOLD}
CERT_THRESHOLD=${CERT_THRESHOLD}
EOF
sudo mv /tmp/resistack-observability.env /etc/default/resistack-observability

cat > /tmp/resistack-observability.service <<'EOF'
[Unit]
Description=ResistanceStack observability snapshot

[Service]
Type=oneshot
EnvironmentFile=/etc/default/resistack-observability
ExecStart=/usr/local/bin/resistack-observe
EOF
sudo mv /tmp/resistack-observability.service /etc/systemd/system/resistack-observability.service

cat > /tmp/resistack-observability.timer <<'EOF'
[Unit]
Description=Run ResistanceStack observability snapshot every 5 minutes

[Timer]
OnBootSec=2m
OnUnitActiveSec=5m
Unit=resistack-observability.service

[Install]
WantedBy=timers.target
EOF
sudo mv /tmp/resistack-observability.timer /etc/systemd/system/resistack-observability.timer

cat > /tmp/resistack-observability-ui.service <<EOF
[Unit]
Description=ResistanceStack local observability panel

[Service]
Type=simple
WorkingDirectory=${DATA_DIR}
ExecStart=/usr/bin/env python3 -m http.server ${PANEL_PORT} --bind ${PANEL_HOST} --directory ${DATA_DIR}
Restart=always
EOF
sudo mv /tmp/resistack-observability-ui.service /etc/systemd/system/resistack-observability-ui.service

sudo systemctl daemon-reload
sudo systemctl enable --now resistack-observability.timer resistack-observability-ui.service
sudo systemctl start resistack-observability.service
echo "[resistack] observability enabled on http://${PANEL_HOST}:${PANEL_PORT}/latest.json"
`, scriptutil.ShellQuote(cfg.Observability.LocalDataDir),
		scriptutil.ShellQuote(host),
		scriptutil.ShellQuote(port),
		scriptutil.ShellQuote(cfg.Alerts.WebhookURL),
		scriptutil.ShellQuote(cfg.Alerts.SlackURL),
		cfg.Alerts.Thresholds.SSHFailures15m,
		cfg.Alerts.Thresholds.Bans15m,
		cfg.Alerts.Thresholds.NginxErrors15m,
		cfg.Alerts.Thresholds.ContainerRestarts,
		cfg.Alerts.Thresholds.DiskPercentUsed,
		cfg.Alerts.Thresholds.CertExpiryDays)
}

func BuildDisableScript(cfg config.Config) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
sudo systemctl disable --now resistack-observability.timer resistack-observability-ui.service >/dev/null 2>&1 || true
sudo rm -f /etc/systemd/system/resistack-observability.service
sudo rm -f /etc/systemd/system/resistack-observability.timer
sudo rm -f /etc/systemd/system/resistack-observability-ui.service
sudo systemctl daemon-reload
echo "[resistack] observability disabled; data retained in %s"
`, scriptutil.ShellQuote(cfg.Observability.LocalDataDir))
}

func splitBind(bind string) (string, string) {
	parts := strings.Split(strings.TrimSpace(bind), ":")
	if len(parts) < 2 {
		return "127.0.0.1", "9400"
	}
	host := strings.Join(parts[:len(parts)-1], ":")
	port := parts[len(parts)-1]
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = "9400"
	}
	return host, port
}
