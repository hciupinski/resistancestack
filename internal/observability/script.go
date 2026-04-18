package observability

import (
	"fmt"
	"path"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/scriptutil"
)

func BuildEnableScript(cfg config.Config) string {
	host, port := splitBind(cfg.Observability.PanelBind)
	paths := buildPaths(cfg.Observability.LocalDataDir)

	var b strings.Builder
	fmt.Fprintf(&b, "#!/usr/bin/env bash\nset -euo pipefail\n")
	fmt.Fprintf(&b, "DATA_DIR=%s\n", scriptutil.ShellQuote(paths.dataDir))
	fmt.Fprintf(&b, "BIN_DIR=%s\n", scriptutil.ShellQuote(paths.binDir))
	fmt.Fprintf(&b, "CONFIG_DIR=%s\n", scriptutil.ShellQuote(paths.configDir))
	fmt.Fprintf(&b, "DOWNLOAD_DIR=%s\n", scriptutil.ShellQuote(paths.downloadDir))
	fmt.Fprintf(&b, "LOG_DIR=%s\n", scriptutil.ShellQuote(paths.logDir))
	fmt.Fprintf(&b, "GRAFANA_HOME=%s\n", scriptutil.ShellQuote(paths.grafanaHome))
	fmt.Fprintf(&b, "GRAFANA_DATA=%s\n", scriptutil.ShellQuote(paths.grafanaData))
	fmt.Fprintf(&b, "GRAFANA_LOGS=%s\n", scriptutil.ShellQuote(paths.grafanaLogs))
	fmt.Fprintf(&b, "GRAFANA_CONFIG=%s\n", scriptutil.ShellQuote(paths.grafanaConfig))
	fmt.Fprintf(&b, "GRAFANA_DASHBOARDS=%s\n", scriptutil.ShellQuote(paths.grafanaDashboards))
	fmt.Fprintf(&b, "GRAFANA_CREDENTIALS=%s\n", scriptutil.ShellQuote(paths.grafanaCreds))
	fmt.Fprintf(&b, "LOKI_DATA=%s\n", scriptutil.ShellQuote(paths.lokiData))
	fmt.Fprintf(&b, "LOKI_CONFIG=%s\n", scriptutil.ShellQuote(paths.lokiConfig))
	fmt.Fprintf(&b, "ALLOY_DATA=%s\n", scriptutil.ShellQuote(paths.alloyData))
	fmt.Fprintf(&b, "ALLOY_CONFIG=%s\n", scriptutil.ShellQuote(paths.alloyConfig))
	fmt.Fprintf(&b, "OBS_ENV_FILE=%s\n", scriptutil.ShellQuote("/etc/default/resistack-observability"))
	fmt.Fprintf(&b, "SNAPSHOT_INTERVAL=%s\n", scriptutil.ShellQuote(systemdInterval(cfg.Observability.SnapshotInterval)))
	fmt.Fprintf(&b, "PANEL_HOST=%s\n", scriptutil.ShellQuote(host))
	fmt.Fprintf(&b, "PANEL_PORT=%s\n", scriptutil.ShellQuote(port))
	fmt.Fprintf(&b, "GRAFANA_VERSION=%s\n", scriptutil.ShellQuote(grafanaVersion))
	fmt.Fprintf(&b, "GRAFANA_BUILD=%s\n", scriptutil.ShellQuote(grafanaBuild))
	fmt.Fprintf(&b, "LOKI_VERSION=%s\n", scriptutil.ShellQuote(lokiVersion))
	fmt.Fprintf(&b, "ALLOY_VERSION=%s\n", scriptutil.ShellQuote(alloyVersion))
	b.WriteString(`
sudo install -d -m 0755 "${DATA_DIR}" "${BIN_DIR}" "${CONFIG_DIR}" "${DOWNLOAD_DIR}" "${LOG_DIR}"
sudo install -d -m 0755 "$(dirname "${GRAFANA_CONFIG}")" "$(dirname "${LOKI_CONFIG}")" "$(dirname "${ALLOY_CONFIG}")" "${GRAFANA_DASHBOARDS}"
sudo install -d -m 0755 "${GRAFANA_DATA}" "${GRAFANA_LOGS}" "${LOKI_DATA}" "${ALLOY_DATA}"

download() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 1 "${url}" -o "${dest}"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "${dest}" "${url}"
    return
  fi
  echo "[resistack] curl or wget is required to install observability binaries" >&2
  exit 1
}

ensure_system_user() {
  local name="$1"
  local home="$2"
  if ! id -u "${name}" >/dev/null 2>&1; then
    sudo useradd --system --home-dir "${home}" --shell /usr/sbin/nologin "${name}"
  fi
}

add_user_to_group_if_present() {
  local name="$1"
  local group_name="$2"
  if getent group "${group_name}" >/dev/null 2>&1; then
    sudo usermod -a -G "${group_name}" "${name}"
  fi
}

python_extract_zip_binary() {
  local archive="$1"
  local binary_name="$2"
  local output="$3"
  python3 - "${archive}" "${binary_name}" "${output}" <<'PY'
import os
import stat
import sys
import zipfile

archive, binary_name, output = sys.argv[1:]
with zipfile.ZipFile(archive) as handle:
    for member in handle.infolist():
        if member.filename.endswith("/"):
            continue
        name = os.path.basename(member.filename)
        if name != binary_name:
            continue
        with handle.open(member) as src, open(output, "wb") as dst:
            dst.write(src.read())
        os.chmod(output, os.stat(output).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        break
    else:
        raise SystemExit(f"missing {binary_name} in {archive}")
PY
}

python_extract_tar_tree() {
  local archive="$1"
  local output_dir="$2"
  python3 - "${archive}" "${output_dir}" <<'PY'
import os
import shutil
import sys
import tarfile
import tempfile

archive, output_dir = sys.argv[1:]
tmp_root = tempfile.mkdtemp(prefix="resistack-grafana-")
try:
    with tarfile.open(archive, "r:gz") as handle:
        handle.extractall(tmp_root)
    children = [
        os.path.join(tmp_root, name)
        for name in os.listdir(tmp_root)
        if os.path.isdir(os.path.join(tmp_root, name))
    ]
    if len(children) != 1:
        raise SystemExit(f"unexpected Grafana archive layout in {archive}")
    staging = children[0]
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    shutil.move(staging, output_dir)
finally:
    shutil.rmtree(tmp_root, ignore_errors=True)
PY
}

install_grafana() {
  local archive="${DOWNLOAD_DIR}/grafana.tar.gz"
  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "[resistack] unsupported architecture for Grafana: $(uname -m)" >&2
      exit 1
      ;;
  esac
  download "https://dl.grafana.com/grafana/release/${GRAFANA_VERSION}/grafana_${GRAFANA_VERSION}_${GRAFANA_BUILD}_linux_${arch}.tar.gz" "${archive}"
  python_extract_tar_tree "${archive}" "${GRAFANA_HOME}"
}

install_loki() {
  local archive="${DOWNLOAD_DIR}/loki.zip"
  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "[resistack] unsupported architecture for Loki: $(uname -m)" >&2
      exit 1
      ;;
  esac
  download "https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/loki-linux-${arch}.zip" "${archive}"
  python_extract_zip_binary "${archive}" "loki-linux-${arch}" "${DOWNLOAD_DIR}/loki"
  sudo install -m 0755 "${DOWNLOAD_DIR}/loki" "${BIN_DIR}/loki"
}

install_alloy() {
  local archive="${DOWNLOAD_DIR}/alloy.zip"
  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "[resistack] unsupported architecture for Alloy: $(uname -m)" >&2
      exit 1
      ;;
  esac
  download "https://github.com/grafana/alloy/releases/download/v${ALLOY_VERSION}/alloy-linux-${arch}.zip" "${archive}"
  python_extract_zip_binary "${archive}" "alloy" "${DOWNLOAD_DIR}/alloy"
  sudo install -m 0755 "${DOWNLOAD_DIR}/alloy" "${BIN_DIR}/alloy"
}

sudo systemctl disable --now resistack-observability.timer resistack-observability-ui.service >/dev/null 2>&1 || true
sudo systemctl stop resistack-observability.service >/dev/null 2>&1 || true
sudo rm -f /etc/systemd/system/resistack-observability.service
sudo rm -f /etc/systemd/system/resistack-observability.timer
sudo rm -f /etc/systemd/system/resistack-observability-ui.service
sudo systemctl stop resistack-grafana.service resistack-loki.service resistack-alloy.service >/dev/null 2>&1 || true

ensure_system_user "resistack-grafana" "${DATA_DIR}"
ensure_system_user "resistack-loki" "${DATA_DIR}"
ensure_system_user "resistack-alloy" "${DATA_DIR}"
add_user_to_group_if_present "resistack-alloy" "adm"
add_user_to_group_if_present "resistack-alloy" "systemd-journal"
add_user_to_group_if_present "resistack-alloy" "docker"

if [ ! -s "${GRAFANA_CREDENTIALS}" ]; then
  admin_password="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)"
  printf 'resistack:%s\n' "${admin_password}" | sudo tee "${GRAFANA_CREDENTIALS}" >/dev/null
  sudo chmod 0640 "${GRAFANA_CREDENTIALS}"
fi

admin_user="$(cut -d: -f1 "${GRAFANA_CREDENTIALS}")"
admin_password="$(cut -d: -f2- "${GRAFANA_CREDENTIALS}")"

install_grafana
install_loki
install_alloy

sudo chown -R resistack-grafana:resistack-grafana "${GRAFANA_HOME}" "${GRAFANA_DATA}" "${GRAFANA_LOGS}"
sudo chown -R resistack-loki:resistack-loki "${LOKI_DATA}"
sudo chown -R resistack-alloy:resistack-alloy "${ALLOY_DATA}"
sudo chown -R root:root "${CONFIG_DIR}" "${BIN_DIR}" "${LOG_DIR}" "${DOWNLOAD_DIR}"
`)

	appendHeredoc(&b, "/tmp/resistack-observe", buildObserveScript())
	b.WriteString("sudo mv /tmp/resistack-observe " + paths.observeBinary + "\n")
	b.WriteString("sudo chmod 0755 " + paths.observeBinary + "\n\n")

	appendHeredoc(&b, "/tmp/resistack-observability.env", buildEnvFile(cfg, paths, host, port))
	b.WriteString("sudo mv /tmp/resistack-observability.env \"${OBS_ENV_FILE}\"\n\n")

	appendHeredoc(&b, "/tmp/resistack-grafana.ini", buildGrafanaConfig(paths, host, port))
	b.WriteString("sed -e \"s#__RESISTACK_ADMIN_PASSWORD__#${admin_password//\\/\\\\}#g\" /tmp/resistack-grafana.ini | sudo tee \"${GRAFANA_CONFIG}\" >/dev/null\n")
	b.WriteString("rm -f /tmp/resistack-grafana.ini\n\n")

	appendHeredoc(&b, "/tmp/resistack-loki.yaml", buildLokiConfig(cfg, paths))
	b.WriteString("sudo mv /tmp/resistack-loki.yaml \"${LOKI_CONFIG}\"\n\n")

	appendHeredoc(&b, "/tmp/resistack-alloy.alloy", buildAlloyConfig(cfg, paths))
	b.WriteString("sudo mv /tmp/resistack-alloy.alloy \"${ALLOY_CONFIG}\"\n\n")

	appendHeredoc(&b, "/tmp/resistack-datasource.yaml", buildDatasourcesProvisioning())
	b.WriteString("sudo mv /tmp/resistack-datasource.yaml \"" + path.Join(paths.grafanaProvision, "datasources", "loki.yaml") + "\"\n\n")

	appendHeredoc(&b, "/tmp/resistack-dashboard-provider.yaml", buildDashboardProvider(paths))
	b.WriteString("sudo mv /tmp/resistack-dashboard-provider.yaml \"" + path.Join(paths.grafanaProvision, "dashboards", "resistack.yaml") + "\"\n\n")

	for name, dashboard := range buildDashboards() {
		tmpPath := "/tmp/" + name
		appendHeredoc(&b, tmpPath, dashboard)
		fmt.Fprintf(&b, "sudo mv %s %s\n\n", scriptutil.ShellQuote(tmpPath), scriptutil.ShellQuote(path.Join(paths.grafanaDashboards, name)))
	}

	appendHeredoc(&b, "/tmp/resistack-observability-snapshot.service", buildSnapshotService(paths))
	b.WriteString("sudo mv /tmp/resistack-observability-snapshot.service /etc/systemd/system/resistack-observability-snapshot.service\n\n")

	appendHeredoc(&b, "/tmp/resistack-observability-snapshot.timer", buildSnapshotTimer(cfg))
	b.WriteString("sudo mv /tmp/resistack-observability-snapshot.timer /etc/systemd/system/resistack-observability-snapshot.timer\n\n")

	appendHeredoc(&b, "/tmp/resistack-loki.service", buildLokiService(paths))
	b.WriteString("sudo mv /tmp/resistack-loki.service /etc/systemd/system/resistack-loki.service\n\n")

	appendHeredoc(&b, "/tmp/resistack-alloy.service", buildAlloyService(paths))
	b.WriteString("sudo mv /tmp/resistack-alloy.service /etc/systemd/system/resistack-alloy.service\n\n")

	appendHeredoc(&b, "/tmp/resistack-grafana.service", buildGrafanaService(paths))
	b.WriteString("sudo mv /tmp/resistack-grafana.service /etc/systemd/system/resistack-grafana.service\n\n")

	b.WriteString(`
sudo chown root:root "${OBS_ENV_FILE}" "${GRAFANA_CONFIG}" "${LOKI_CONFIG}" "${ALLOY_CONFIG}"
sudo chmod 0644 "${OBS_ENV_FILE}" "${GRAFANA_CONFIG}" "${LOKI_CONFIG}" "${ALLOY_CONFIG}"
sudo chown -R root:root "${GRAFANA_DASHBOARDS}" "${CONFIG_DIR}"
sudo chown -R root:root "$(dirname "${GRAFANA_CONFIG}")"

sudo systemctl daemon-reload
sudo systemctl enable --now resistack-loki.service resistack-alloy.service resistack-grafana.service resistack-observability-snapshot.timer
sudo systemctl start resistack-observability-snapshot.service

echo "[resistack] observability enabled on http://${PANEL_HOST}:${PANEL_PORT}/"
echo "[resistack] grafana credentials: ${GRAFANA_CREDENTIALS}"
`)
	return b.String()
}

func BuildDisableScript(cfg config.Config) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
sudo systemctl disable --now resistack-observability-snapshot.timer resistack-grafana.service resistack-loki.service resistack-alloy.service >/dev/null 2>&1 || true
sudo systemctl stop resistack-observability-snapshot.service >/dev/null 2>&1 || true
sudo rm -f /etc/systemd/system/resistack-observability-snapshot.service
sudo rm -f /etc/systemd/system/resistack-observability-snapshot.timer
sudo rm -f /etc/systemd/system/resistack-grafana.service
sudo rm -f /etc/systemd/system/resistack-loki.service
sudo rm -f /etc/systemd/system/resistack-alloy.service
sudo rm -f /etc/systemd/system/resistack-observability.service
sudo rm -f /etc/systemd/system/resistack-observability.timer
sudo rm -f /etc/systemd/system/resistack-observability-ui.service
sudo rm -f /etc/default/resistack-observability
sudo systemctl daemon-reload
echo "[resistack] observability disabled; data retained in %s"
`, scriptutil.ShellQuote(cfg.Observability.LocalDataDir))
}

func buildObserveScript() string {
	return `#!/usr/bin/env python3
import glob
import json
import os
import re
import subprocess
import urllib.request
from datetime import datetime, timedelta, timezone
from time import perf_counter

DATA_DIR = os.environ["DATA_DIR"]
LOG_DIR = os.environ["LOG_DIR"]
LATEST_PATH = os.environ["LATEST_PATH"]
SNAPSHOT_GLOB = os.environ["SNAPSHOT_GLOB"]
SECURITY_GLOB = os.environ["SECURITY_GLOB"]
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
SLACK_URL = os.environ.get("SLACK_URL", "")
HOST_METRICS = os.environ.get("HOST_METRICS", "false").lower() == "true"
HEALTHCHECK_URLS = json.loads(os.environ.get("HEALTHCHECK_URLS", "[]"))
SSH_THRESHOLD = int(os.environ["SSH_THRESHOLD"])
BAN_THRESHOLD = int(os.environ["BAN_THRESHOLD"])
NGINX_THRESHOLD = int(os.environ["NGINX_THRESHOLD"])
CONTAINER_RESTART_THRESHOLD = int(os.environ["CONTAINER_RESTART_THRESHOLD"])
DISK_THRESHOLD = int(os.environ["DISK_THRESHOLD"])
CERT_THRESHOLD = int(os.environ["CERT_THRESHOLD"])
RETENTION_DAYS = int(os.environ["RETENTION_DAYS"])

os.makedirs(LOG_DIR, exist_ok=True)
now = datetime.now(timezone.utc)
day_suffix = now.strftime("%Y%m%d")
snapshot_path = os.path.join(LOG_DIR, f"snapshot-{day_suffix}.ndjson")
security_path = os.path.join(LOG_DIR, f"security-{day_suffix}.ndjson")


def run(command):
    return subprocess.run(command, text=True, capture_output=True)


def text(command):
    result = run(command)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def emit_line(path, payload):
    payload.setdefault("timestamp", now.isoformat())
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    os.chmod(path, 0o644)


def service_state(name):
    result = run(["systemctl", "is-active", name])
    status = result.stdout.strip() if result.returncode == 0 else "inactive"
    enabled = run(["systemctl", "is-enabled", name]).returncode == 0
    return {"enabled": enabled, "status": status}


def parse_banned_ips():
    raw = text(["bash", "-lc", "fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\\s*//p' || true"])
    jails = [jail.strip() for jail in raw.split(",") if jail.strip()]
    results = []
    for jail in jails:
        output = text(["bash", "-lc", f"fail2ban-client status {jail!r} 2>/dev/null || true"])
        for line in output.splitlines():
            if "Banned IP list:" not in line:
                continue
            ips = [ip for ip in line.split(":", 1)[1].strip().split() if ip]
            for ip in ips:
                results.append({"jail": jail, "ip": ip})
    return results


def parse_healthchecks():
    results = []
    for raw_url in HEALTHCHECK_URLS:
        started = perf_counter()
        status = "healthy"
        error = ""
        code = 0
        try:
            request = urllib.request.Request(raw_url, headers={"User-Agent": "resistack-observe/1"})
            with urllib.request.urlopen(request, timeout=5) as response:
                code = getattr(response, "status", 0) or 0
                response.read(512)
                if code >= 400:
                    status = "degraded"
        except Exception as exc:
            status = "down"
            error = str(exc)
        latency_ms = round((perf_counter() - started) * 1000, 2)
        results.append(
            {
                "url": raw_url,
                "status": status,
                "status_code": code,
                "latency_ms": latency_ms,
                "error": error,
            }
        )
    return results


ssh_logs = text(["bash", "-lc", "journalctl -u ssh --since '-15 minutes' --no-pager 2>/dev/null || journalctl -u sshd --since '-15 minutes' --no-pager 2>/dev/null || true"])
fail2ban_logs = text(["bash", "-lc", "journalctl -u fail2ban --since '-15 minutes' --no-pager 2>/dev/null || true"])
nginx_logs = text(["bash", "-lc", "tail -n 400 /var/log/nginx/access.log 2>/dev/null || true"])
nginx_errors = 0
for line in nginx_logs.splitlines():
    if re.search(r'"\s([45]\d\d)\s', line):
        nginx_errors += 1

containers = []
docker_ids = text(["bash", "-lc", "docker ps -q 2>/dev/null || true"]).splitlines()
for container_id in docker_ids:
    inspect = text(["bash", "-lc", f"docker inspect {container_id} 2>/dev/null"])
    if not inspect:
        continue
    data = json.loads(inspect)[0]
    containers.append(
        {
            "name": data.get("Name", "").lstrip("/"),
            "image": data.get("Config", {}).get("Image", ""),
            "status": data.get("State", {}).get("Status", ""),
            "restarts": data.get("RestartCount", 0),
        }
    )

certificates = []
for fullchain in glob.glob("/etc/letsencrypt/live/*/fullchain.pem"):
    expiry = text(["bash", "-lc", f"openssl x509 -in {fullchain!r} -noout -enddate 2>/dev/null | cut -d= -f2-"])
    days_remaining = None
    if expiry:
        try:
            expires_at = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = max(0, int((expires_at - now).total_seconds() // 86400))
        except ValueError:
            days_remaining = None
    certificates.append(
        {
            "path": fullchain,
            "expires_at": expiry,
            "days_remaining": days_remaining,
        }
    )

disk_percent = None
service_states = []
if HOST_METRICS:
    disk_output = text(["bash", "-lc", "df -P / | tail -n 1 | awk '{print $5}' | tr -d '%'"])
    disk_percent = int(disk_output) if disk_output.isdigit() else 0
    for service_name in ("nginx", "docker", "fail2ban"):
        state = service_state(service_name)
        service_states.append({"service": service_name, "status": state["status"], "enabled": state["enabled"]})

healthchecks = parse_healthchecks()
blocked_ips = parse_banned_ips()

payload = {
    "generated_at": now.isoformat(),
    "ssh_failures_15m": len(re.findall(r"Failed password|Invalid user", ssh_logs)),
    "bans_15m": len(re.findall(r" Ban ", fail2ban_logs)),
    "nginx_errors_15m": nginx_errors,
    "containers": containers,
    "disk_percent_used": disk_percent,
    "certificates": certificates,
    "service_states": service_states,
    "healthchecks": healthchecks,
    "blocked_ips": blocked_ips,
}

with open(LATEST_PATH, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
os.chmod(LATEST_PATH, 0o644)

emit_line(
    snapshot_path,
    {
        "source": "resistack_snapshot",
        "kind": "snapshot",
        "event": "summary",
        "ssh_failures_15m": payload["ssh_failures_15m"],
        "bans_15m": payload["bans_15m"],
        "nginx_errors_15m": payload["nginx_errors_15m"],
        "disk_percent_used": payload["disk_percent_used"],
        "healthchecks_configured": len(healthchecks),
        "containers_running": len(containers),
    },
)

for service in service_states:
    emit_line(
        snapshot_path,
        {
            "source": "resistack_snapshot",
            "kind": "snapshot",
            "event": "service_state",
            "service": service["service"],
            "status": service["status"],
            "enabled": service["enabled"],
        },
    )

for container in containers:
    emit_line(
        snapshot_path,
        {
            "source": "resistack_snapshot",
            "kind": "snapshot",
            "event": "container_state",
            "service": container["name"],
            "image": container["image"],
            "status": container["status"],
            "restarts": container["restarts"],
        },
    )

for cert in certificates:
    emit_line(
        snapshot_path,
        {
            "source": "resistack_snapshot",
            "kind": "snapshot",
            "event": "certificate",
            "service": "tls",
            "path": cert["path"],
            "expires_at": cert["expires_at"],
            "days_remaining": cert["days_remaining"],
        },
    )

for item in healthchecks:
    emit_line(
        snapshot_path,
        {
            "source": "resistack_snapshot",
            "kind": "snapshot",
            "event": "healthcheck",
            "service": "healthcheck",
            "url": item["url"],
            "status": item["status"],
            "status_code": item["status_code"],
            "latency_ms": item["latency_ms"],
            "error": item["error"],
        },
    )

for banned in blocked_ips:
    emit_line(
        security_path,
        {
            "source": "resistack_snapshot",
            "kind": "security",
            "event": "blocked_ip",
            "service": "fail2ban",
            "jail": banned["jail"],
            "ip": banned["ip"],
            "active": True,
        },
    )

emit_line(
    security_path,
    {
        "source": "resistack_snapshot",
        "kind": "security",
        "event": "security_summary",
        "service": "resistack",
        "active_bans": len(blocked_ips),
        "ssh_failures_15m": payload["ssh_failures_15m"],
        "bans_15m": payload["bans_15m"],
        "nginx_errors_15m": payload["nginx_errors_15m"],
    },
)

alerts = []
if payload["ssh_failures_15m"] >= SSH_THRESHOLD:
    alerts.append("ssh_bruteforce")
if payload["bans_15m"] >= BAN_THRESHOLD:
    alerts.append("ban_burst")
if payload["nginx_errors_15m"] >= NGINX_THRESHOLD:
    alerts.append("nginx_4xx_5xx_anomaly")
if any(item["restarts"] >= CONTAINER_RESTART_THRESHOLD for item in containers):
    alerts.append("container_restarts")
if disk_percent is not None and disk_percent >= DISK_THRESHOLD:
    alerts.append("disk_pressure")
if any((cert.get("days_remaining") is not None and cert["days_remaining"] <= CERT_THRESHOLD) for cert in certificates):
    alerts.append("certificate_expiry_window")

if alerts:
    emit_line(
        security_path,
        {
            "source": "resistack_snapshot",
            "kind": "security",
            "event": "alert",
            "service": "resistack",
            "alerts": alerts,
        },
    )
    outgoing = json.dumps({"alerts": alerts, "snapshot": payload}).encode("utf-8")
    for endpoint in (WEBHOOK_URL, SLACK_URL):
        if not endpoint:
            continue
        try:
            req = urllib.request.Request(endpoint, data=outgoing, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).read()
        except Exception:
            pass

cutoff = now - timedelta(days=RETENTION_DAYS)
for pattern in (SNAPSHOT_GLOB, SECURITY_GLOB):
    for candidate in glob.glob(pattern):
        if datetime.fromtimestamp(os.path.getmtime(candidate), tz=timezone.utc) < cutoff:
            try:
                os.remove(candidate)
            except OSError:
                pass
`
}

func buildSnapshotService(paths observabilityPaths) string {
	return fmt.Sprintf(`[Unit]
Description=ResistanceStack observability snapshot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/default/resistack-observability
ExecStart=%s
`, paths.observeBinary)
}

func buildSnapshotTimer(cfg config.Config) string {
	return fmt.Sprintf(`[Unit]
Description=Run ResistanceStack observability snapshot

[Timer]
OnBootSec=2m
OnUnitActiveSec=%s
Unit=resistack-observability-snapshot.service

[Install]
WantedBy=timers.target
`, systemdInterval(cfg.Observability.SnapshotInterval))
}

func buildLokiService(paths observabilityPaths) string {
	return fmt.Sprintf(`[Unit]
Description=ResistanceStack Loki
After=network-online.target
Wants=network-online.target

[Service]
User=resistack-loki
Group=resistack-loki
ExecStart=%s -config.file=%s
Restart=always
WorkingDirectory=%s

[Install]
WantedBy=multi-user.target
`, path.Join(paths.binDir, "loki"), paths.lokiConfig, paths.lokiData)
}

func buildAlloyService(paths observabilityPaths) string {
	return fmt.Sprintf(`[Unit]
Description=ResistanceStack Grafana Alloy
After=network-online.target resistack-loki.service
Wants=network-online.target

[Service]
User=resistack-alloy
Group=resistack-alloy
ExecStart=%s run %s --storage.path=%s
Restart=always
WorkingDirectory=%s

[Install]
WantedBy=multi-user.target
`, path.Join(paths.binDir, "alloy"), paths.alloyConfig, paths.alloyData, paths.alloyData)
}

func buildGrafanaService(paths observabilityPaths) string {
	return fmt.Sprintf(`[Unit]
Description=ResistanceStack Grafana
After=network-online.target resistack-loki.service
Wants=network-online.target

[Service]
User=resistack-grafana
Group=resistack-grafana
WorkingDirectory=%s
ExecStart=%s server --homepath=%s --config=%s
Restart=always

[Install]
WantedBy=multi-user.target
`, paths.grafanaHome, path.Join(paths.grafanaHome, "bin", "grafana"), paths.grafanaHome, paths.grafanaConfig)
}

func appendHeredoc(b *strings.Builder, target string, content string) {
	fmt.Fprintf(b, "cat > %s <<'EOF'\n%s\nEOF\n\n", scriptutil.ShellQuote(target), content)
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
