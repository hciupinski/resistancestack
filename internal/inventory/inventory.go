package inventory

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/hciupinski/resistancestack/internal/ci"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

type Snapshot struct {
	CollectedAt     time.Time         `json:"collected_at"`
	Host            HostInfo          `json:"host"`
	Proxy           ProxyInfo         `json:"proxy"`
	Runtime         RuntimeInfo       `json:"runtime"`
	ExposedPorts    []PortInfo        `json:"exposed_ports"`
	TLSCertificates []TLSCertificate  `json:"tls_certificates"`
	SSHUsers        []string          `json:"ssh_users"`
	SudoUsers       []string          `json:"sudo_users"`
	UFW             ServiceState      `json:"ufw"`
	Fail2ban        ServiceState      `json:"fail2ban"`
	LogLocations    []string          `json:"log_locations"`
	Containers      []ContainerInfo   `json:"containers"`
	Repo            RepoInfo          `json:"repo"`
	Observability   ObservabilityInfo `json:"observability"`
}

type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Kernel   string `json:"kernel"`
}

type ProxyInfo struct {
	Kind   string   `json:"kind"`
	Active bool     `json:"active"`
	Notes  []string `json:"notes"`
}

type RuntimeInfo struct {
	Kind         string   `json:"kind"`
	ComposeFiles []string `json:"compose_files"`
	SystemdUnits []string `json:"systemd_units"`
}

type PortInfo struct {
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	Address string `json:"address"`
	Public  bool   `json:"public"`
}

type TLSCertificate struct {
	Domain    string `json:"domain"`
	ExpiresAt string `json:"expires_at"`
}

type ServiceState struct {
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"`
}

type ContainerInfo struct {
	Name     string `json:"name"`
	Image    string `json:"image"`
	Status   string `json:"status"`
	Restarts int    `json:"restarts"`
}

type RepoInfo struct {
	GitHubWorkflows []string       `json:"github_workflows"`
	ComposeFiles    []string       `json:"compose_files"`
	NginxPaths      []string       `json:"nginx_paths"`
	SystemdUnits    []string       `json:"systemd_units"`
	Technologies    []string       `json:"technologies"`
	TechProfile     ci.TechProfile `json:"tech_profile"`
}

type ObservabilityInfo struct {
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"`
}

func Collect(cfg config.Config, root string) (Snapshot, error) {
	target := remote.Target{
		Host:            cfg.Server.Host,
		User:            cfg.Server.SSHUser,
		Port:            cfg.Server.SSHPort,
		KeyPath:         cfg.Server.PrivateKeyPath,
		HostKeyChecking: cfg.Server.HostKeyChecking,
		KnownHostsPath:  cfg.Server.KnownHostsPath,
	}

	raw, err := remote.CaptureScript(target, buildRemoteInventoryScript(cfg))
	if err != nil {
		return Snapshot{}, err
	}

	var snapshot Snapshot
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode inventory: %w", err)
	}
	repo, err := collectRepoInfo(root, cfg)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Repo = repo
	return snapshot, nil
}

func collectRepoInfo(root string, cfg config.Config) (RepoInfo, error) {
	profile, err := ci.DetectTech(root)
	if err != nil {
		return RepoInfo{}, err
	}
	workflows, err := DetectGitHubWorkflows(root)
	if err != nil {
		return RepoInfo{}, err
	}
	composeFiles, err := DetectComposeFiles(root, cfg.AppInventory.ComposePaths)
	if err != nil {
		return RepoInfo{}, err
	}
	nginxPaths, err := DetectNginxPaths(root, cfg.AppInventory.NginxPaths)
	if err != nil {
		return RepoInfo{}, err
	}
	systemdUnits, err := DetectSystemdUnits(root, cfg.AppInventory.SystemdUnits)
	if err != nil {
		return RepoInfo{}, err
	}

	technologies := []string{}
	if len(profile.NodeProjects) > 0 {
		technologies = append(technologies, "node")
		for _, project := range profile.NodeProjects {
			if project.Framework == "nextjs" {
				technologies = append(technologies, "nextjs")
				break
			}
		}
	}
	if len(profile.DotnetProjects) > 0 {
		technologies = append(technologies, ".net")
	}
	if len(profile.Dockerfiles) > 0 || len(profile.ComposeFiles) > 0 || len(composeFiles) > 0 {
		technologies = append(technologies, "docker")
	}
	technologies = dedupeStrings(technologies)

	return RepoInfo{
		GitHubWorkflows: workflows,
		ComposeFiles:    composeFiles,
		NginxPaths:      nginxPaths,
		SystemdUnits:    systemdUnits,
		Technologies:    technologies,
		TechProfile:     profile,
	}, nil
}

func buildRemoteInventoryScript(cfg config.Config) string {
	domains := strings.Join(cfg.AppInventory.Domains, ",")
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
export RESISTACK_DOMAINS=%s
python3 - <<'PY'
import glob
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
    domain = fullchain.split("/")[-2]
    expires = text(["bash", "-lc", f"openssl x509 -in {fullchain!r} -noout -enddate 2>/dev/null | cut -d= -f2-"])
    certs.append({"domain": domain, "expires_at": expires})

ssh_users = []
for line in text(["bash", "-lc", "getent passwd | awk -F: '$7 !~ /(nologin|false)$/ {print $1}'"]).splitlines():
    if line:
        ssh_users.append(line)

sudo_users = []
sudo_line = text(["bash", "-lc", "getent group sudo || getent group wheel || true"])
if sudo_line:
    members = sudo_line.split(":")[-1].split(",")
    sudo_users = [member for member in members if member]

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
    "ufw": {"enabled": "Status: active" in text(["bash", "-lc", "sudo ufw status 2>/dev/null || true"]), "status": text(["bash", "-lc", "sudo ufw status 2>/dev/null | head -n1 || true"])},
    "fail2ban": service_state("fail2ban"),
    "log_locations": log_locations,
    "containers": containers,
    "observability": {"enabled": obs_enabled, "status": obs_state},
}
print(json.dumps(snapshot))
PY
`, shellQuote(domains))
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

func shellQuote(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

func RepoRelative(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
