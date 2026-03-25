package hosthardening

import (
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

type AccessPlan struct {
	Mode                   string
	CurrentOperatorIP      string
	PreserveCurrentSession bool
	StaticAllowlist        []string
	EffectiveAllowlist     []string
	BootstrapCIDR          string
	OpenSSHGlobally        bool
	BlockingReason         string
	FinalRuleModel         string
}

func Apply(cfg config.Config, dryRun bool, out io.Writer, errOut io.Writer) error {
	target := remote.Target{
		Host:            cfg.Server.Host,
		User:            cfg.Server.SSHUser,
		Port:            cfg.Server.SSHPort,
		KeyPath:         cfg.Server.PrivateKeyPath,
		HostKeyChecking: cfg.Server.HostKeyChecking,
		KnownHostsPath:  cfg.Server.KnownHostsPath,
	}

	if dryRun {
		plan, previewErr := PreviewAccessPlan(target, cfg)
		if previewErr != nil {
			fmt.Fprintf(errOut, "warning: unable to derive current SSH session for dry-run: %v\n", previewErr)
			plan = BuildAccessPlan(cfg, "")
		}
		fmt.Fprintln(out, FormatAccessPlan(plan))
		fmt.Fprintln(out, "Generated host-hardening script:")
		fmt.Fprintln(out, BuildApplyScript(cfg))
		if plan.BlockingReason != "" {
			return fmt.Errorf("host hardening preview failed: %s", plan.BlockingReason)
		}
		return nil
	}

	return remote.RunScript(target, BuildApplyScript(cfg), out, errOut)
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

func PreviewAccessPlan(target remote.Target, cfg config.Config) (AccessPlan, error) {
	raw, err := remote.Capture(target, `printf '%s' "${SSH_CONNECTION:-}"`)
	if err != nil {
		return AccessPlan{}, err
	}
	currentIP, err := ParseCurrentOperatorIP(strings.TrimSpace(raw))
	if err != nil {
		return BuildAccessPlan(cfg, ""), err
	}
	return BuildAccessPlan(cfg, currentIP), nil
}

func ParseCurrentOperatorIP(raw string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return "", fmt.Errorf("SSH_CONNECTION is empty")
	}
	if len(fields) != 4 {
		return "", fmt.Errorf("SSH_CONNECTION must contain 4 tokens, got %d", len(fields))
	}
	addr, err := netip.ParseAddr(fields[0])
	if err != nil {
		return "", fmt.Errorf("parse SSH source IP: %w", err)
	}
	return addr.String(), nil
}

func BuildAccessPlan(cfg config.Config, currentOperatorIP string) AccessPlan {
	mode := cfg.HostHardening.UFWPolicy.OperatorAccessMode
	if strings.TrimSpace(mode) == "" {
		mode = config.OperatorAccessModePublicHardened
	}

	plan := AccessPlan{
		Mode:                   mode,
		CurrentOperatorIP:      strings.TrimSpace(currentOperatorIP),
		PreserveCurrentSession: cfg.HostHardening.UFWPolicy.PreserveCurrentSession,
		StaticAllowlist:        sanitizeAllowlist(cfg.HostHardening.UFWPolicy.AdminAllowlist),
	}
	plan.EffectiveAllowlist = append([]string{}, plan.StaticAllowlist...)

	currentIPValid := false
	if plan.CurrentOperatorIP != "" {
		_, err := netip.ParseAddr(plan.CurrentOperatorIP)
		currentIPValid = err == nil
	}

	if currentIPValid && plan.PreserveCurrentSession && !ipInAllowlist(plan.CurrentOperatorIP, plan.StaticAllowlist) {
		plan.BootstrapCIDR = cidrForIP(plan.CurrentOperatorIP)
		plan.EffectiveAllowlist = append(plan.EffectiveAllowlist, plan.BootstrapCIDR)
	}

	switch mode {
	case config.OperatorAccessModeAllowlistOnly:
		if !currentIPValid {
			plan.BlockingReason = "unable to derive current SSH client IP for allowlist_only mode"
		} else if len(plan.EffectiveAllowlist) == 0 {
			plan.BlockingReason = "no effective SSH allowlist available for allowlist_only mode"
		} else if !ipInAllowlist(plan.CurrentOperatorIP, plan.EffectiveAllowlist) {
			plan.BlockingReason = fmt.Sprintf("current SSH client IP %s is outside the effective allowlist", plan.CurrentOperatorIP)
		}
	default:
		if len(plan.StaticAllowlist) == 0 {
			plan.OpenSSHGlobally = true
		} else if plan.PreserveCurrentSession && !currentIPValid {
			plan.BlockingReason = "unable to derive current SSH client IP while preserve_current_session=true and static allowlist rules are configured"
		}
	}

	switch {
	case plan.OpenSSHGlobally:
		plan.FinalRuleModel = fmt.Sprintf("global SSH access on tcp/%d with key-only hardening", cfg.Server.SSHPort)
	case len(plan.StaticAllowlist) > 0:
		plan.FinalRuleModel = fmt.Sprintf("static allowlist on tcp/%d", cfg.Server.SSHPort)
	default:
		plan.FinalRuleModel = fmt.Sprintf("no static allowlist on tcp/%d", cfg.Server.SSHPort)
	}
	if plan.BootstrapCIDR != "" {
		plan.FinalRuleModel += fmt.Sprintf(" + bootstrap %s", plan.BootstrapCIDR)
	}
	if mode == config.OperatorAccessModeAllowlistOnly {
		plan.FinalRuleModel = "allowlist-only " + plan.FinalRuleModel
	}

	return plan
}

func FormatAccessPlan(plan AccessPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host hardening access preview:\n")
	fmt.Fprintf(&b, "- operator access mode: %s\n", plan.Mode)
	if plan.CurrentOperatorIP == "" {
		fmt.Fprintf(&b, "- current source IP: unavailable\n")
	} else {
		fmt.Fprintf(&b, "- current source IP: %s\n", plan.CurrentOperatorIP)
	}
	fmt.Fprintf(&b, "- preserve current session: %t\n", plan.PreserveCurrentSession)
	if len(plan.StaticAllowlist) == 0 {
		fmt.Fprintf(&b, "- static admin allowlist: none\n")
	} else {
		fmt.Fprintf(&b, "- static admin allowlist: %s\n", strings.Join(plan.StaticAllowlist, ", "))
	}
	if plan.BootstrapCIDR == "" {
		fmt.Fprintf(&b, "- bootstrap current session: no\n")
	} else {
		fmt.Fprintf(&b, "- bootstrap current session: yes (%s)\n", plan.BootstrapCIDR)
	}
	fmt.Fprintf(&b, "- final SSH rule model: %s\n", plan.FinalRuleModel)
	if plan.BlockingReason != "" {
		fmt.Fprintf(&b, "- apply would fail: %s\n", plan.BlockingReason)
	}
	return strings.TrimRight(b.String(), "\n")
}

func BuildApplyScript(cfg config.Config) string {
	allowUsers := ""
	if len(cfg.HostHardening.SSHHardening.AllowUsers) > 0 {
		allowUsers = strings.Join(cfg.HostHardening.SSHHardening.AllowUsers, " ")
	}

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

	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

BACKUP_ROOT=%s
SSH_PORT=%d
ALLOW_USERS=%s
REQUIRE_PASSWORDLESS_SUDO=%s
STATIC_ADMIN_ALLOWLIST=%s
OPERATOR_ACCESS_MODE=%s
PRESERVE_CURRENT_SESSION=%s

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

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y ufw fail2ban
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
		shellQuote(strings.Join(sanitizeAllowlist(cfg.HostHardening.UFWPolicy.AdminAllowlist), ",")),
		shellQuote(operatorAccessMode),
		shellQuote(boolString(cfg.HostHardening.UFWPolicy.PreserveCurrentSession)),
		cfg.Server.SSHUser,
		cfg.Server.SSHUser,
		cfg.Server.SSHUser,
		cfg.Server.SSHUser,
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

func ipInAllowlist(rawIP string, allowlist []string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return false
	}
	for _, entry := range allowlist {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(entry))
		if err != nil {
			continue
		}
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
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
