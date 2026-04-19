package hosthardening

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/scriptutil"
)

func BuildApplyScript(cfg config.Config) string {
	allowUsers := strings.Join(config.ManagedSSHAllowUsers(cfg), " ")
	primaryDomain := cfg.PrimaryDomain()

	ufwTCPRules := strings.Builder{}
	for _, port := range cfg.HostHardening.UFWPolicy.AllowedTCPPorts {
		if port == cfg.Server.SSHPort {
			continue
		}
		fmt.Fprintf(&ufwTCPRules, "sudo ufw allow %d/tcp\n", port)
	}
	ufwUDPRules := strings.Builder{}
	for _, port := range cfg.HostHardening.UFWPolicy.AllowedUDPPorts {
		fmt.Fprintf(&ufwUDPRules, "sudo ufw allow %d/udp\n", port)
	}

	passwordlessCheck := "false"
	if cfg.HostHardening.SSHHardening.RequirePasswordlessSudo {
		passwordlessCheck = "true"
	}

	packageList := []string{"ufw", "fail2ban"}
	if cfg.HostHardening.SSLCertificates.Enabled {
		packageList = append(packageList, "certbot")
	}

	automaticUpdates := ""
	if cfg.HostHardening.AutomaticSecurityUpdates {
		automaticUpdates = `
sudo apt-get install -y unattended-upgrades
cat > /tmp/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
backup_file /etc/apt/apt.conf.d/20auto-upgrades
sudo mv /tmp/20auto-upgrades /etc/apt/apt.conf.d/20auto-upgrades
append_manifest /etc/apt/apt.conf.d/20auto-upgrades
`
	}

	dockerCheck := ""
	if cfg.HostHardening.CheckDockerDaemon {
		dockerCheck = `
if sudo test -f /etc/docker/daemon.json; then
  if sudo grep -q '2375' /etc/docker/daemon.json; then
    echo "[resistack] warning: docker daemon.json contains TCP listener hints" >&2
  fi
fi
`
	}

	operatorAccessMode := cfg.HostHardening.UFWPolicy.OperatorAccessMode
	if operatorAccessMode == "" {
		operatorAccessMode = config.OperatorAccessModePublicHardened
	}

	sslWorkflow := ""
	if cfg.HostHardening.SSLCertificates.Enabled {
		sslWorkflow = `
ensure_managed_certificate
`
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

BACKUP_ROOT=%s
SSH_PORT=%d
PRIMARY_SSH_USER=%s
ALLOW_USERS=%s
DISABLE_ROOT_LOGIN=%s
DISABLE_PASSWORD_AUTH=%s
REQUIRE_PASSWORDLESS_SUDO=%s
STATIC_ADMIN_ALLOWLIST=%s
OPERATOR_ACCESS_MODE=%s
PRESERVE_CURRENT_SESSION=%s
SSL_CERTIFICATES_ENABLED=%s
SSL_CERTIFICATES_AUTO_ISSUE=%s
SSL_PRIMARY_DOMAIN=%s
SSL_EMAIL=%s
SSL_STAGING=%s

require_privileged_access() {
  if [ "$(id -u)" -eq 0 ]; then
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    echo "[resistack] sudo is required for host hardening" >&2
    exit 1
  fi
  if sudo -n true >/dev/null 2>&1; then
    return 0
  fi
  echo "[resistack] passwordless sudo is required for host hardening" >&2
  echo "[resistack] configure it for user %s, for example:" >&2
  echo "[resistack]   echo '%s ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/resistack-%s" >&2
  echo "[resistack]   sudo chmod 440 /etc/sudoers.d/resistack-%s" >&2
  echo "[resistack] then verify: sudo -n true && echo OK" >&2
  exit 1
}

parse_current_operator_ip() {
  python3 - <<'PY'
import ipaddress
import os
import sys

raw = os.environ.get("SSH_CONNECTION", "").split()
if len(raw) != 4:
    sys.exit(0)
try:
    ip = ipaddress.ip_address(raw[0])
except ValueError:
    sys.exit(0)
print(ip)
PY
}

ip_in_allowlist() {
  python3 - "$1" "$2" <<'PY'
import ipaddress
import sys

allowlist = [item.strip() for item in sys.argv[1].split(",") if item.strip()]
raw_ip = sys.argv[2].strip()
if not allowlist or not raw_ip:
    raise SystemExit(1)
ip = ipaddress.ip_address(raw_ip)
for item in allowlist:
    if ip in ipaddress.ip_network(item, strict=False):
        raise SystemExit(0)
raise SystemExit(1)
PY
}

cidr_for_ip() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

ip = ipaddress.ip_address(sys.argv[1].strip())
suffix = "32" if ip.version == 4 else "128"
print(f"{ip}/{suffix}")
PY
}

append_csv() {
  local current="$1"
  local item="$2"
  if [ -z "${current}" ]; then
    printf '%%s' "${item}"
    return 0
  fi
  printf '%%s,%%s' "${current}" "${item}"
}

getent_field() {
  local user="$1"
  local field="$2"
  getent passwd "${user}" | cut -d: -f"${field}"
}

has_interactive_shell() {
  local user="$1"
  local shell_path
  shell_path="$(getent_field "${user}" 7 || true)"
  [ -n "${shell_path}" ] || return 1
  case "${shell_path}" in
    */nologin|*/false)
      return 1
      ;;
  esac
  return 0
}

has_authorized_keys() {
  local user="$1"
  local home_dir
  home_dir="$(getent_field "${user}" 6 || true)"
  [ -n "${home_dir}" ] || return 1
  sudo test -s "${home_dir}/.ssh/authorized_keys"
}

require_ssh_login_candidate() {
  local user="$1"
  if ! getent passwd "${user}" >/dev/null 2>&1; then
    echo "[resistack] refusing to change SSH access controls: user ${user} does not exist" >&2
    exit 1
  fi
  if ! has_interactive_shell "${user}"; then
    echo "[resistack] refusing to change SSH access controls: user ${user} has a non-interactive shell" >&2
    exit 1
  fi
  if [ "${DISABLE_PASSWORD_AUTH}" = "true" ] && ! has_authorized_keys "${user}"; then
    echo "[resistack] refusing to change SSH access controls: user ${user} has no authorized_keys for key-only login" >&2
    exit 1
  fi
}

verify_future_ssh_access() {
  local user
  local usable_candidates=0

  if [ -n "${ALLOW_USERS}" ]; then
    for user in ${ALLOW_USERS}; do
      if [ "${DISABLE_ROOT_LOGIN}" = "true" ] && [ "${user}" = "root" ]; then
        continue
      fi
      require_ssh_login_candidate "${user}"
      usable_candidates=$((usable_candidates + 1))
    done
    if [ "${usable_candidates}" -eq 0 ]; then
      echo "[resistack] refusing to change SSH access controls: AllowUsers would leave no usable non-root SSH login after root is disabled" >&2
      exit 1
    fi
    return 0
  fi

  if [ "${DISABLE_ROOT_LOGIN}" = "true" ] && [ "${PRIMARY_SSH_USER}" = "root" ]; then
    echo "[resistack] refusing to disable root login without an explicit non-root allow_users entry" >&2
    echo "[resistack] bootstrap a named sudo user with authorized_keys, then add it to host_hardening.ssh_hardening.allow_users" >&2
    exit 1
  fi

  require_ssh_login_candidate "${PRIMARY_SSH_USER}"
}

cleanup_bootstrap_rules() {
  local status_output
  local numbers
  status_output="$(sudo ufw status numbered 2>/dev/null || true)"
  numbers="$(
    printf '%%s\n' "${status_output}" | python3 -c '
import re
import sys

matches = []
for line in sys.stdin:
    if "resistack-bootstrap" not in line:
        continue
    match = re.match(r"\[\s*(\d+)\]", line)
    if match:
        matches.append(int(match.group(1)))
for item in reversed(matches):
    print(item)
'
  )"
  if [ -z "${numbers}" ]; then
    return 0
  fi
  while IFS= read -r number; do
    [ -z "${number}" ] && continue
    sudo ufw --force delete "${number}" >/dev/null 2>&1 || true
  done <<EOF
${numbers}
EOF
}

apply_static_allowlist_rules() {
  local cidr
  IFS=',' read -r -a cidrs <<< "${STATIC_ADMIN_ALLOWLIST}"
  for cidr in "${cidrs[@]}"; do
    [ -z "${cidr}" ] && continue
    sudo ufw allow from "${cidr}" to any port "${SSH_PORT}" proto tcp
  done
}

STOPPED_PROXY_SERVICES=""

restore_proxy_services() {
  local service
  IFS=',' read -r -a services <<< "${STOPPED_PROXY_SERVICES}"
  for service in "${services[@]}"; do
    [ -z "${service}" ] && continue
    sudo systemctl start "${service}" >/dev/null 2>&1 || true
  done
  STOPPED_PROXY_SERVICES=""
}

trap restore_proxy_services EXIT

port_80_in_use() {
  ss -tulpnH 2>/dev/null | python3 -c '
import sys

for line in sys.stdin:
    parts = line.split()
    if len(parts) < 5:
        continue
    local = parts[4]
    if local.endswith(":80") or local.endswith("]:80") or local == "*:80":
        raise SystemExit(0)
raise SystemExit(1)
'
}

find_certbot_managed_certificate_lineage() {
  sudo python3 - "$1" <<'PY'
import subprocess
import sys

target = sys.argv[1].strip().lower()
if not target:
    raise SystemExit(1)

def covers_domain(name, domain):
    name = name.strip().lower()
    if not name:
        return False
    if name == domain:
        return True
    if not name.startswith("*."):
        return False
    suffix = name[2:]
    if not suffix or not domain.endswith("." + suffix):
        return False
    return domain.count(".") == suffix.count(".") + 1

result = subprocess.run(["certbot", "certificates"], text=True, capture_output=True)
if result.returncode != 0:
    raise SystemExit(2)

entries = []
current = None
for raw_line in result.stdout.splitlines():
    line = raw_line.strip()
    if line.startswith("Certificate Name:"):
        if current:
            entries.append(current)
        current = {
            "cert_name": line.split(":", 1)[1].strip(),
            "domains": [],
            "certificate_path": "",
        }
        continue
    if not current:
        continue
    if line.startswith("Domains:"):
        current["domains"] = [item.strip() for item in line.split(":", 1)[1].split() if item.strip()]
        continue
    if line.startswith("Certificate Path:"):
        current["certificate_path"] = line.split(":", 1)[1].strip()
if current:
    entries.append(current)

for entry in entries:
    if any(name.strip().lower() == target for name in entry["domains"]):
        print(f"{entry['cert_name']}\t{entry['certificate_path']}")
        raise SystemExit(0)
for entry in entries:
    if any(covers_domain(name, target) for name in entry["domains"]):
        print(f"{entry['cert_name']}\t{entry['certificate_path']}")
        raise SystemExit(0)
raise SystemExit(1)
PY
}

validate_certbot_managed_lineage() {
  local cert_name="$1"
  local fullchain="$2"
  local expected_fullchain="/etc/letsencrypt/live/${cert_name}/fullchain.pem"
  local lineage_dir="/etc/letsencrypt/live/${cert_name}"
  local renewal_conf="/etc/letsencrypt/renewal/${cert_name}.conf"
  [ -n "${cert_name}" ] || return 1
  [ -n "${fullchain}" ] || return 1
  [ "${fullchain}" = "${expected_fullchain}" ] || return 1
  sudo test -d "${lineage_dir}" || return 1
  sudo test -f "${renewal_conf}" || return 1
  sudo test -f "${lineage_dir}/fullchain.pem" || return 1
  sudo test -f "${lineage_dir}/privkey.pem" || return 1
}

find_filesystem_matching_certificate_path() {
  sudo python3 - "$1" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

target = sys.argv[1].strip().lower()
if not target:
    raise SystemExit(1)

def text(command):
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()

def covers_domain(name, domain):
    name = name.strip().lower()
    if not name:
        return False
    if name == domain:
        return True
    if not name.startswith("*."):
        return False
    suffix = name[2:]
    if not suffix or not domain.endswith("." + suffix):
        return False
    return domain.count(".") == suffix.count(".") + 1

fallback = ""
for fullchain in sorted(Path("/etc/letsencrypt/live").glob("*/fullchain.pem")):
    names = []
    san_output = text(["openssl", "x509", "-in", str(fullchain), "-noout", "-ext", "subjectAltName"])
    subject_output = text(["openssl", "x509", "-in", str(fullchain), "-noout", "-subject", "-nameopt", "RFC2253"])
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
    if not any(covers_domain(name, target) for name in names):
        continue
    if subprocess.run(["openssl", "x509", "-in", str(fullchain), "-noout", "-checkend", "0"], capture_output=True).returncode == 0:
        print(fullchain)
        raise SystemExit(0)
    if not fallback:
        fallback = str(fullchain)
if fallback:
    print(fallback)
    raise SystemExit(0)
raise SystemExit(1)
PY
}

find_matching_certificate_path() {
  local target="$1"
  local certbot_lineage=""
  certbot_lineage="$(find_certbot_managed_certificate_lineage "${target}")"
  local status="$?"
  if [ "${status}" -eq 0 ]; then
    printf '%%s\n' "${certbot_lineage#*	}"
    return 0
  fi
  if [ "${status}" -eq 2 ]; then
    return 2
  fi
  find_filesystem_matching_certificate_path "${target}"
}

certificate_is_valid() {
  local fullchain="$1"
  [ -n "${fullchain}" ] || return 1
  sudo openssl x509 -in "${fullchain}" -noout -checkend 0 >/dev/null 2>&1
}

stop_known_proxy_for_certbot() {
  local service
  for service in nginx traefik; do
    if ! sudo systemctl is-active --quiet "${service}"; then
      continue
    fi
    echo "[resistack] stopping ${service} to free tcp/80 for certbot"
    sudo systemctl stop "${service}"
    STOPPED_PROXY_SERVICES="$(append_csv "${STOPPED_PROXY_SERVICES}" "${service}")"
    if ! port_80_in_use; then
      return 0
    fi
  done
  return 1
}

ensure_managed_certificate() {
  if [ "${SSL_CERTIFICATES_ENABLED}" != "true" ] || [ -z "${SSL_PRIMARY_DOMAIN}" ]; then
    return 0
  fi

  certificate_path=""
  certificate_exists="false"
  cert_name=""
  certbot_lineage=""
  certbot_lookup_status=1
  if certbot_lineage="$(find_certbot_managed_certificate_lineage "${SSL_PRIMARY_DOMAIN}")"; then
    certbot_lookup_status=0
    IFS=$'\t' read -r cert_name certificate_path <<< "${certbot_lineage}"
    if ! validate_certbot_managed_lineage "${cert_name}" "${certificate_path}"; then
      echo "[resistack] certbot reports managed lineage ${cert_name} for ${SSL_PRIMARY_DOMAIN}, but its local files or renewal config are inconsistent" >&2
      echo "[resistack] repair or delete /etc/letsencrypt/live/${cert_name} and /etc/letsencrypt/renewal/${cert_name}.conf before requesting a new certificate" >&2
      exit 1
    fi
    certificate_exists="true"
    echo "[resistack] selected certbot-managed lineage for ${SSL_PRIMARY_DOMAIN}: ${cert_name} (${certificate_path})"
    if certificate_is_valid "${certificate_path}"; then
      echo "[resistack] valid TLS certificate already present for ${SSL_PRIMARY_DOMAIN}: ${certificate_path}"
      return 0
    fi
    echo "[resistack] existing TLS certificate for ${SSL_PRIMARY_DOMAIN} is expired or invalid: ${certificate_path}"
  else
    certbot_lookup_status="$?"
    if [ "${certbot_lookup_status}" -eq 2 ]; then
      echo "[resistack] warning: unable to inspect certbot-managed lineages locally; falling back to filesystem detection" >&2
    elif filesystem_certificate_path="$(find_filesystem_matching_certificate_path "${SSL_PRIMARY_DOMAIN}")"; then
      echo "[resistack] found matching certificate files for ${SSL_PRIMARY_DOMAIN}: ${filesystem_certificate_path}" >&2
      echo "[resistack] certbot does not report a managed lineage for this domain; repair the local certbot lineage before requesting a new certificate" >&2
      exit 1
    fi
  fi

  if [ "${SSL_CERTIFICATES_AUTO_ISSUE}" != "true" ]; then
    echo "[resistack] skipping Let's Encrypt issuance for ${SSL_PRIMARY_DOMAIN}: auto_issue=false" >&2
    return 0
  fi

  if port_80_in_use && ! stop_known_proxy_for_certbot; then
    echo "[resistack] tcp/80 is in use by an unmanaged process; stop it manually before requesting a Let's Encrypt certificate for ${SSL_PRIMARY_DOMAIN}" >&2
    exit 1
  fi
  if port_80_in_use; then
    echo "[resistack] tcp/80 is still busy after stopping known proxies; cannot run certbot standalone for ${SSL_PRIMARY_DOMAIN}" >&2
    exit 1
  fi

  certbot_args=(
    certonly
    --standalone
    --non-interactive
    --agree-tos
    --email "${SSL_EMAIL}"
    -d "${SSL_PRIMARY_DOMAIN}"
  )
  if [ "${certificate_exists}" = "true" ] && [ -n "${cert_name}" ]; then
    certbot_args+=(--cert-name "${cert_name}" --force-renewal)
  fi
  if [ "${SSL_STAGING}" = "true" ]; then
    certbot_args+=(--staging)
  fi

  echo "[resistack] issuing Let's Encrypt certificate for ${SSL_PRIMARY_DOMAIN}"
  sudo certbot "${certbot_args[@]}"
  restore_proxy_services

  if ! certbot_lineage="$(find_certbot_managed_certificate_lineage "${SSL_PRIMARY_DOMAIN}")"; then
    echo "[resistack] certbot finished, but no managed certificate lineage matched ${SSL_PRIMARY_DOMAIN} in local certbot inventory" >&2
    exit 1
  fi
  IFS=$'\t' read -r cert_name certificate_path <<< "${certbot_lineage}"
  if ! validate_certbot_managed_lineage "${cert_name}" "${certificate_path}"; then
    echo "[resistack] certbot issued a lineage for ${SSL_PRIMARY_DOMAIN}, but the resulting files or renewal config are inconsistent" >&2
    exit 1
  fi
  echo "[resistack] selected certificate lineage for post-issue verification: ${certificate_path}"
  if ! certificate_is_valid "${certificate_path}"; then
    echo "[resistack] certbot finished but no valid certificate was detected for ${SSL_PRIMARY_DOMAIN}" >&2
    exit 1
  fi
  echo "[resistack] certificate ready for ${SSL_PRIMARY_DOMAIN}: ${certificate_path}"
}

require_privileged_access

timestamp="$(date -u +%%Y%%m%%d%%H%%M%%S)"
op_dir="${BACKUP_ROOT}/${timestamp}"
manifest="${op_dir}/manifest.txt"
sudo install -d -m 0700 "${BACKUP_ROOT}" "${op_dir}"
sudo ln -sfn "${op_dir}" "${BACKUP_ROOT}/last"
sudo touch "${manifest}"

append_manifest() {
  printf '%%s\n' "$1" | sudo tee -a "${manifest}" >/dev/null
}

backup_file() {
  local path="$1"
  local rel="${path#/}"
  local dest="${op_dir}/${rel}"
  sudo install -d -m 0700 "$(dirname "${dest}")"
  if sudo test -f "${path}"; then
    sudo cp -a "${path}" "${dest}"
    append_manifest "${path}"
  fi
}

restart_ssh_service() {
  if sudo systemctl restart ssh >/dev/null 2>&1; then
    return 0
  fi
  if sudo systemctl restart sshd >/dev/null 2>&1; then
    return 0
  fi
  if sudo service ssh restart >/dev/null 2>&1; then
    return 0
  fi
  if sudo service sshd restart >/dev/null 2>&1; then
    return 0
  fi
  echo "[resistack] unable to restart SSH service: tried ssh and sshd via systemd and service" >&2
  exit 1
}

ensure_sshd_option() {
  local key="$1"
  local value="$2"
  local file="/etc/ssh/sshd_config"
  if sudo grep -qE "^[#[:space:]]*${key}[[:space:]]+" "${file}"; then
    sudo sed -i -E "s|^[#[:space:]]*${key}[[:space:]]+.*|${key} ${value}|g" "${file}"
  else
    printf '%%s %%s\n' "${key}" "${value}" | sudo tee -a "${file}" >/dev/null
  fi
}

if [ "${REQUIRE_PASSWORDLESS_SUDO}" = "true" ]; then
  require_privileged_access
fi

verify_future_ssh_access

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y %s
else
  echo "unsupported package manager for host hardening" >&2
  exit 1
fi

CURRENT_OPERATOR_IP="$(parse_current_operator_ip)"
EFFECTIVE_ALLOWLIST="${STATIC_ADMIN_ALLOWLIST}"
BOOTSTRAP_CIDR=""
OPEN_SSH_GLOBALLY="false"
BLOCKING_REASON=""

if [ -n "${CURRENT_OPERATOR_IP}" ] && [ "${PRESERVE_CURRENT_SESSION}" = "true" ]; then
  if ! ip_in_allowlist "${STATIC_ADMIN_ALLOWLIST}" "${CURRENT_OPERATOR_IP}"; then
    BOOTSTRAP_CIDR="$(cidr_for_ip "${CURRENT_OPERATOR_IP}")"
    EFFECTIVE_ALLOWLIST="$(append_csv "${EFFECTIVE_ALLOWLIST}" "${BOOTSTRAP_CIDR}")"
  fi
fi

if [ "${OPERATOR_ACCESS_MODE}" = "public_hardened" ]; then
  if [ -z "${STATIC_ADMIN_ALLOWLIST}" ]; then
    OPEN_SSH_GLOBALLY="true"
  elif [ "${PRESERVE_CURRENT_SESSION}" = "true" ] && [ -z "${CURRENT_OPERATOR_IP}" ]; then
    BLOCKING_REASON="unable to derive current SSH client IP while preserve_current_session=true and static allowlist rules are configured"
  fi
else
  if [ -z "${CURRENT_OPERATOR_IP}" ]; then
    BLOCKING_REASON="unable to derive current SSH client IP for allowlist_only mode"
  elif [ -z "${EFFECTIVE_ALLOWLIST}" ]; then
    BLOCKING_REASON="no effective SSH allowlist available for allowlist_only mode"
  elif ! ip_in_allowlist "${EFFECTIVE_ALLOWLIST}" "${CURRENT_OPERATOR_IP}"; then
    BLOCKING_REASON="current SSH client IP ${CURRENT_OPERATOR_IP} is outside the effective SSH allowlist"
  fi
fi

FINAL_SSH_RULE_MODEL="static allowlist on tcp/${SSH_PORT}"
if [ "${OPEN_SSH_GLOBALLY}" = "true" ]; then
  FINAL_SSH_RULE_MODEL="global SSH access on tcp/${SSH_PORT} with key-only hardening"
fi
if [ -n "${BOOTSTRAP_CIDR}" ]; then
  FINAL_SSH_RULE_MODEL="${FINAL_SSH_RULE_MODEL} + bootstrap ${BOOTSTRAP_CIDR}"
fi
if [ "${OPERATOR_ACCESS_MODE}" = "allowlist_only" ]; then
  FINAL_SSH_RULE_MODEL="allowlist-only ${FINAL_SSH_RULE_MODEL}"
fi

echo "[resistack] operator access mode: ${OPERATOR_ACCESS_MODE}"
if [ -n "${CURRENT_OPERATOR_IP}" ]; then
  echo "[resistack] detected current source IP: ${CURRENT_OPERATOR_IP}"
else
  echo "[resistack] detected current source IP: unavailable"
fi
if [ -n "${BOOTSTRAP_CIDR}" ]; then
  echo "[resistack] bootstrap current session: yes (${BOOTSTRAP_CIDR})"
else
  echo "[resistack] bootstrap current session: no"
fi
echo "[resistack] final SSH rule model: ${FINAL_SSH_RULE_MODEL}"

if [ -n "${BLOCKING_REASON}" ]; then
  echo "[resistack] refusing to change host firewall: ${BLOCKING_REASON}" >&2
  exit 1
fi

backup_file /etc/ssh/sshd_config
ensure_sshd_option PermitRootLogin %s
ensure_sshd_option PasswordAuthentication %s
ensure_sshd_option PubkeyAuthentication yes
ensure_sshd_option MaxAuthTries %d
ensure_sshd_option LoginGraceTime %d
if [ -n "${ALLOW_USERS}" ]; then
  ensure_sshd_option AllowUsers "${ALLOW_USERS}"
fi
sudo sshd -t
append_manifest /etc/ssh/sshd_config

backup_file /etc/fail2ban/jail.d/resistack-sshd.local
cat > /tmp/resistack-sshd.local <<'EOF'
[DEFAULT]
bantime = %s
findtime = %s
maxretry = %d
backend = systemd

[sshd]
enabled = %s
mode = aggressive

[recidive]
enabled = %s
bantime = %s
findtime = 1d
maxretry = 5
EOF
sudo install -d -m 0755 /etc/fail2ban/jail.d
sudo mv /tmp/resistack-sshd.local /etc/fail2ban/jail.d/resistack-sshd.local
append_manifest /etc/fail2ban/jail.d/resistack-sshd.local

sudo ufw --force disable >/dev/null 2>&1 || true
sudo ufw default %s incoming
sudo ufw default %s outgoing
cleanup_bootstrap_rules
if [ "${OPEN_SSH_GLOBALLY}" = "true" ]; then
  sudo ufw allow "${SSH_PORT}/tcp"
else
  apply_static_allowlist_rules
  if [ -n "${BOOTSTRAP_CIDR}" ]; then
    sudo ufw allow from "${BOOTSTRAP_CIDR}" to any port "${SSH_PORT}" proto tcp comment 'resistack-bootstrap'
  fi
fi
%s%s
sudo ufw --force enable

%s
sudo systemctl restart fail2ban
restart_ssh_service

%s
%s

if %t; then
  require_ssh_login_candidate %s
fi
sudo -n -l >/dev/null

echo "[resistack] host hardening applied"
`, scriptutil.ShellQuote(cfg.HostHardening.BackupDir),
		cfg.Server.SSHPort,
		scriptutil.ShellQuote(cfg.Server.SSHUser),
		scriptutil.ShellQuote(allowUsers),
		scriptutil.ShellQuote(boolString(cfg.HostHardening.SSHHardening.DisableRootLogin)),
		scriptutil.ShellQuote(boolString(cfg.HostHardening.SSHHardening.DisablePasswordAuth)),
		scriptutil.ShellQuote(passwordlessCheck),
		scriptutil.ShellQuote(strings.Join(sanitizeAllowlist(cfg.HostHardening.UFWPolicy.AdminAllowlist), ",")),
		scriptutil.ShellQuote(operatorAccessMode),
		scriptutil.ShellQuote(boolString(cfg.HostHardening.UFWPolicy.PreserveCurrentSession)),
		scriptutil.ShellQuote(boolString(cfg.HostHardening.SSLCertificates.Enabled)),
		scriptutil.ShellQuote(boolString(cfg.HostHardening.SSLCertificates.AutoIssue)),
		scriptutil.ShellQuote(primaryDomain),
		scriptutil.ShellQuote(cfg.HostHardening.SSLCertificates.Email),
		scriptutil.ShellQuote(boolString(cfg.HostHardening.SSLCertificates.Staging)),
		cfg.Server.SSHUser,
		cfg.Server.SSHUser,
		cfg.Server.SSHUser,
		cfg.Server.SSHUser,
		strings.Join(packageList, " "),
		yesNo(!cfg.HostHardening.SSHHardening.DisableRootLogin, "prohibit-password", "no"),
		yesNo(!cfg.HostHardening.SSHHardening.DisablePasswordAuth, "yes", "no"),
		cfg.HostHardening.SSHHardening.MaxAuthTries,
		cfg.HostHardening.SSHHardening.LoginGraceTimeSeconds,
		cfg.HostHardening.Fail2ban.BanTime,
		cfg.HostHardening.Fail2ban.FindTime,
		cfg.HostHardening.Fail2ban.MaxRetry,
		boolString(cfg.HostHardening.Fail2ban.Enabled),
		boolString(cfg.HostHardening.Fail2ban.RecidiveEnabled),
		cfg.HostHardening.Fail2ban.RecidiveBanTime,
		cfg.HostHardening.UFWPolicy.DefaultIncoming,
		cfg.HostHardening.UFWPolicy.DefaultOutgoing,
		ufwTCPRules.String(),
		ufwUDPRules.String(),
		sslWorkflow,
		automaticUpdates,
		dockerCheck,
		cfg.HostHardening.CheckDeployUser,
		scriptutil.ShellQuote(cfg.Server.SSHUser))
}

func BuildRollbackScript(cfg config.Config) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
BACKUP_ROOT=%s
latest="$(readlink -f "${BACKUP_ROOT}/last" 2>/dev/null || true)"
if [ -z "${latest}" ] || [ ! -f "${latest}/manifest.txt" ]; then
  echo "no host backup available" >&2
  exit 1
fi

while IFS= read -r original; do
  [ -z "${original}" ] && continue
  backup="${latest}/${original#/}"
  if [ -f "${backup}" ]; then
    sudo install -d -m 0700 "$(dirname "${original}")"
    sudo cp -a "${backup}" "${original}"
  fi
done < "${latest}/manifest.txt"

restart_ssh_service() {
  sudo systemctl restart ssh >/dev/null 2>&1 || \
  sudo systemctl restart sshd >/dev/null 2>&1 || \
  sudo service ssh restart >/dev/null 2>&1 || \
  sudo service sshd restart >/dev/null 2>&1 || true
}

sudo systemctl restart fail2ban || true
restart_ssh_service
sudo ufw reload || true
echo "[resistack] restored host files from ${latest}"
`, scriptutil.ShellQuote(cfg.HostHardening.BackupDir))
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func yesNo(condition bool, yes string, no string) string {
	if condition {
		return yes
	}
	return no
}

func PortsToStrings(ports []int) []string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}
	return values
}

func sanitizeAllowlist(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}

func cidrForIP(rawIP string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return ""
	}
	if ip.Is4() {
		return ip.String() + "/32"
	}
	return ip.String() + "/128"
}
