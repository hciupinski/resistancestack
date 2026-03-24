package hosthardening

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

func Apply(cfg config.Config, dryRun bool, out io.Writer, errOut io.Writer) error {
	target := remote.Target{
		Host:            cfg.Server.Host,
		User:            cfg.Server.SSHUser,
		Port:            cfg.Server.SSHPort,
		KeyPath:         cfg.Server.PrivateKeyPath,
		HostKeyChecking: cfg.Server.HostKeyChecking,
		KnownHostsPath:  cfg.Server.KnownHostsPath,
	}
	script := BuildApplyScript(cfg)
	if dryRun {
		_, _ = fmt.Fprintln(out, script)
		return nil
	}
	return remote.RunScript(target, script, out, errOut)
}

func Rollback(cfg config.Config, out io.Writer, errOut io.Writer) error {
	target := remote.Target{
		Host:            cfg.Server.Host,
		User:            cfg.Server.SSHUser,
		Port:            cfg.Server.SSHPort,
		KeyPath:         cfg.Server.PrivateKeyPath,
		HostKeyChecking: cfg.Server.HostKeyChecking,
		KnownHostsPath:  cfg.Server.KnownHostsPath,
	}
	return remote.RunScript(target, BuildRollbackScript(cfg), out, errOut)
}

func BuildApplyScript(cfg config.Config) string {
	allowUsers := ""
	if len(cfg.HostHardening.SSHHardening.AllowUsers) > 0 {
		allowUsers = strings.Join(cfg.HostHardening.SSHHardening.AllowUsers, " ")
	}

	ufwTCPRules := strings.Builder{}
	for _, port := range cfg.HostHardening.UFWPolicy.AllowedTCPPorts {
		fmt.Fprintf(&ufwTCPRules, "sudo ufw allow %d/tcp\n", port)
	}
	ufwUDPRules := strings.Builder{}
	for _, port := range cfg.HostHardening.UFWPolicy.AllowedUDPPorts {
		fmt.Fprintf(&ufwUDPRules, "sudo ufw allow %d/udp\n", port)
	}
	ufwAdminRules := strings.Builder{}
	for _, cidr := range cfg.HostHardening.UFWPolicy.AdminAllowlist {
		fmt.Fprintf(&ufwAdminRules, "sudo ufw allow from %s to any port %d proto tcp\n", shellQuote(cidr), cfg.Server.SSHPort)
	}
	if ufwAdminRules.Len() == 0 {
		fmt.Fprintf(&ufwAdminRules, "sudo ufw allow %d/tcp\n", cfg.Server.SSHPort)
	}

	passwordlessCheck := "false"
	if cfg.HostHardening.SSHHardening.RequirePasswordlessSudo {
		passwordlessCheck = "true"
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

	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

BACKUP_ROOT=%s
SSH_PORT=%d
ALLOW_USERS=%s
REQUIRE_PASSWORDLESS_SUDO=%s

sudo -n true >/dev/null

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

validate_current_operator() {
  local current_ip="${SSH_CONNECTION%% *}"
  if [ -z "${current_ip}" ]; then
    return 0
  fi
  python3 - %s "${current_ip}" <<'PY'
import ipaddress
import sys

raw = sys.argv[1]
current_ip = sys.argv[2]
allowlist = [item.strip() for item in raw.split(",") if item.strip()]
if not allowlist:
    raise SystemExit(0)
ip = ipaddress.ip_address(current_ip)
if not any(ip in ipaddress.ip_network(item, strict=False) for item in allowlist):
    print(f"current SSH client {current_ip} is outside host_hardening.ufw_policy.admin_allowlist", file=sys.stderr)
    raise SystemExit(1)
PY
}

if [ "${REQUIRE_PASSWORDLESS_SUDO}" = "true" ]; then
  sudo -n true >/dev/null
fi

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y ufw fail2ban
else
  echo "unsupported package manager for host hardening" >&2
  exit 1
fi

validate_current_operator

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
%s%s%s
sudo ufw --force enable

sudo systemctl restart fail2ban
if systemctl list-unit-files | grep -q '^ssh.service'; then
  sudo systemctl restart ssh
else
  sudo systemctl restart sshd
fi

%s
%s

if %t; then
  id %s >/dev/null 2>&1 || { echo "deploy user %s not found" >&2; exit 1; }
fi
sudo -n -l >/dev/null

echo "[resistack] host hardening applied"
`, shellQuote(cfg.HostHardening.BackupDir),
		cfg.Server.SSHPort,
		shellQuote(allowUsers),
		shellQuote(passwordlessCheck),
		shellQuote(strings.Join(cfg.HostHardening.UFWPolicy.AdminAllowlist, ",")),
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
		ufwAdminRules.String(),
		ufwTCPRules.String(),
		ufwUDPRules.String(),
		automaticUpdates,
		dockerCheck,
		cfg.HostHardening.CheckDeployUser,
		shellQuote(cfg.Server.SSHUser),
		shellQuote(cfg.Server.SSHUser))
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

sudo systemctl restart fail2ban || true
if systemctl list-unit-files | grep -q '^ssh.service'; then
  sudo systemctl restart ssh || true
else
  sudo systemctl restart sshd || true
fi
sudo ufw reload || true
echo "[resistack] restored host files from ${latest}"
`, shellQuote(cfg.HostHardening.BackupDir))
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func shellQuote(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
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
