package inventory

import (
	"fmt"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/scriptutil"
	"path/filepath"
	"strings"
)

func buildRemoteInventoryScript(cfg config.Config) string {
	domains := strings.Join(cfg.AppInventory.Domains, ",")
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
export RESISTACK_DOMAINS=%s
python3 - <<'PY'
import glob
import ipaddress
import json
import os
import re
import subprocess
from datetime import datetime, timezone

def run(command):
    return subprocess.run(command, text=True, capture_output=True)

def text(command):
    result = run(command)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()

def service_state(name):
    result = run(["systemctl", "is-active", name])
    status = result.stdout.strip() if result.returncode == 0 else "inactive"
    enabled = run(["systemctl", "is-enabled", name]).returncode == 0
    return {"enabled": enabled, "status": status}

proxy_kind = "none"
proxy_notes = []
if service_state("nginx")["status"] == "active":
    proxy_kind = "nginx"
elif service_state("traefik")["status"] == "active":
    proxy_kind = "traefik"
else:
    docker_ps = text(["bash", "-lc", "sudo docker ps --format '{{.Names}}' 2>/dev/null || true"])
    if "traefik" in docker_ps:
        proxy_kind = "traefik"
        proxy_notes.append("detected via docker container")

runtime_kind = "unknown"
compose_files = []
if text(["bash", "-lc", "sudo docker compose ls --format json 2>/dev/null || true"]):
    runtime_kind = "docker-compose"
docker_active = service_state("docker")["status"] == "active"
if runtime_kind == "unknown" and docker_active:
    runtime_kind = "plain-docker"

systemd_units = []
for unit in ("docker", "nginx", "fail2ban"):
    if service_state(unit)["status"] == "active":
        systemd_units.append(unit)
if runtime_kind == "unknown" and systemd_units:
    runtime_kind = "systemd"

ports = []
for line in text(["bash", "-lc", "ss -tulpnH 2>/dev/null || true"]).splitlines():
    parts = line.split()
    if len(parts) < 5:
        continue
    proto = parts[0]
    local = parts[4]
    if ":" not in local:
        continue
    address, port = local.rsplit(":", 1)
    try:
        port_num = int(port)
    except ValueError:
        continue
    public = address in ("0.0.0.0", "*", "[::]")
    ports.append({"proto": proto, "port": port_num, "address": address, "public": public})

certs = []
for fullchain in glob.glob("/etc/letsencrypt/live/*/fullchain.pem"):
    enddate_output = text(["openssl", "x509", "-in", fullchain, "-noout", "-enddate"])
    expires = enddate_output.split("=", 1)[1] if "=" in enddate_output else ""
    san_output = text(["openssl", "x509", "-in", fullchain, "-noout", "-ext", "subjectAltName"])
    subject_output = text(["openssl", "x509", "-in", fullchain, "-noout", "-subject", "-nameopt", "RFC2253"])

    names = []
    for raw_name in re.findall(r"DNS:([^,\s]+)", san_output):
        name = raw_name.strip()
        if name and name not in names:
            names.append(name)
    subject = subject_output.strip()
    if subject.startswith("subject="):
        subject = subject.split("=", 1)[1]
    for part in subject.split(","):
        if not part.startswith("CN="):
            continue
        name = part.split("=", 1)[1].strip()
        if name and name not in names:
            names.append(name)

    valid = run(["openssl", "x509", "-in", fullchain, "-noout", "-checkend", "0"]).returncode == 0
    certs.append({"path": fullchain, "names": names, "expires_at": expires, "valid": valid})

ssh_users = []
for line in text(["bash", "-lc", "getent passwd | awk -F: '$7 !~ /(nologin|false)$/ {print $1}'"]).splitlines():
    if line:
        ssh_users.append(line)

sudo_users = []
sudo_line = text(["bash", "-lc", "getent group sudo || getent group wheel || true"])
if sudo_line:
    members = sudo_line.split(":")[-1].split(",")
    sudo_users = [member for member in members if member]

passwordless_sudo = False
if text(["id", "-u"]) == "0":
    passwordless_sudo = True
else:
    passwordless_sudo = run(["bash", "-lc", "sudo -n true >/dev/null 2>&1"]).returncode == 0

log_locations = []
for candidate in ("/var/log/nginx/access.log", "/var/log/nginx/error.log", "/var/log/fail2ban.log", "/var/log/auth.log", "/var/log/syslog", "/var/lib/docker/containers"):
    if os.path.exists(candidate):
        log_locations.append(candidate)

containers = []
docker_ids = text(["bash", "-lc", "sudo docker ps -q 2>/dev/null || true"]).splitlines()
for container_id in docker_ids:
    inspect = text(["bash", "-lc", f"sudo docker inspect {container_id} 2>/dev/null"])
    if not inspect:
        continue
    data = json.loads(inspect)[0]
    containers.append({
        "name": data.get("Name", "").lstrip("/"),
        "image": data.get("Config", {}).get("Image", ""),
        "status": data.get("State", {}).get("Status", ""),
        "restarts": data.get("RestartCount", 0),
    })

obs_enabled = os.path.exists("/etc/systemd/system/resistack-observability.timer")
obs_state = "disabled"
if obs_enabled:
    obs_state = text(["systemctl", "is-active", "resistack-observability.timer"]) or "inactive"

snapshot = {
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "current_session_ip": "",
    "host": {
        "hostname": text(["hostname"]),
        "os": text(["bash", "-lc", ". /etc/os-release && printf '%%s' \"$PRETTY_NAME\""]),
        "kernel": text(["uname", "-r"]),
    },
    "proxy": {"kind": proxy_kind, "active": proxy_kind != "none", "notes": proxy_notes},
    "runtime": {"kind": runtime_kind, "compose_files": compose_files, "systemd_units": systemd_units},
    "exposed_ports": ports,
    "tls_certificates": certs,
    "ssh_users": ssh_users,
    "sudo_users": sudo_users,
    "passwordless_sudo": passwordless_sudo,
    "ufw": {"enabled": "Status: active" in text(["bash", "-lc", "sudo ufw status 2>/dev/null || true"]), "status": text(["bash", "-lc", "sudo ufw status 2>/dev/null | head -n1 || true"])},
    "fail2ban": service_state("fail2ban"),
    "log_locations": log_locations,
    "containers": containers,
    "observability": {"enabled": obs_enabled, "status": obs_state},
}
ssh_connection = os.environ.get("SSH_CONNECTION", "").split()
if len(ssh_connection) == 4:
    try:
        ipaddress.ip_address(ssh_connection[0])
        snapshot["current_session_ip"] = ssh_connection[0]
    except ValueError:
        pass
print(json.dumps(snapshot))
PY
`, scriptutil.ShellQuote(domains))
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func RepoRelative(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func LookupCertificateForDomain(certs []TLSCertificate, domain string) (TLSCertificate, TLSCertificateStatus) {
	target := strings.ToLower(strings.TrimSpace(domain))
	if target == "" {
		return TLSCertificate{}, TLSCertificateStatusMissing
	}

	var invalidMatch TLSCertificate
	for _, cert := range certs {
		if !certificateMatchesDomain(cert, target) {
			continue
		}
		if cert.Valid {
			return cert, TLSCertificateStatusValid
		}
		if invalidMatch.Path == "" {
			invalidMatch = cert
		}
	}
	if invalidMatch.Path != "" {
		return invalidMatch, TLSCertificateStatusInvalid
	}
	return TLSCertificate{}, TLSCertificateStatusMissing
}

func certificateMatchesDomain(cert TLSCertificate, domain string) bool {
	for _, rawName := range cert.Names {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" {
			continue
		}
		if name == domain {
			return true
		}
		if wildcardMatchesDomain(name, domain) {
			return true
		}
	}
	return false
}

func wildcardMatchesDomain(pattern string, domain string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(pattern, "*.")
	if suffix == "" || !strings.HasSuffix(domain, "."+suffix) {
		return false
	}
	return strings.Count(domain, ".") == strings.Count(suffix, ".")+1
}
