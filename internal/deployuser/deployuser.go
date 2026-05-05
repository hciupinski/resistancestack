package deployuser

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/fsutil"
	"github.com/hciupinski/resistancestack/internal/remote"
	"github.com/hciupinski/resistancestack/internal/scriptutil"
)

type Options struct {
	User              string
	ConnectAs         string
	PublicKey         string
	PublicKeyPath     string
	SudoMode          string
	AcceptSudoAllRisk bool
}

func Check(cfg config.Config, opts Options, out io.Writer, errOut io.Writer) error {
	resolved, err := ResolveOptions(cfg, opts)
	if err != nil {
		return err
	}
	target := targetForUser(cfg, resolved.ConnectAs)
	return remote.RunScript(target, BuildCheckScript(resolved), out, errOut)
}

func Bootstrap(cfg config.Config, opts Options, dryRun bool, out io.Writer, errOut io.Writer) error {
	resolved, err := ResolveOptions(cfg, opts)
	if err != nil {
		return err
	}
	if resolved.SudoMode == config.SudoModeFull && !resolved.AcceptSudoAllRisk {
		return fmt.Errorf("host_hardening.sudo_mode=full grants NOPASSWD:ALL; pass --accept-sudo-all-risk to bootstrap with this risk")
	}
	fmt.Fprint(out, RiskReport(resolved))
	if dryRun {
		fmt.Fprintf(out, "Deploy user bootstrap plan:\n- connect as: %s\n- deploy user: %s\n- public key: %s\n- sudo mode: %s\n", resolved.ConnectAs, resolved.User, resolved.PublicKeyPath, resolved.SudoMode)
		fmt.Fprintln(out, "Generated deploy-user bootstrap script:")
		fmt.Fprintln(out, BuildBootstrapScript(resolved))
		return nil
	}
	target := targetForUser(cfg, resolved.ConnectAs)
	return remote.RunScript(target, BuildBootstrapScript(resolved), out, errOut)
}

func ResolveOptions(cfg config.Config, opts Options) (Options, error) {
	resolved := Options{
		User:              strings.TrimSpace(opts.User),
		ConnectAs:         strings.TrimSpace(opts.ConnectAs),
		SudoMode:          strings.ToLower(strings.TrimSpace(opts.SudoMode)),
		AcceptSudoAllRisk: opts.AcceptSudoAllRisk,
	}
	if resolved.User == "" {
		resolved.User = config.PreferredDeployUser(cfg)
	}
	if resolved.User == "" {
		return Options{}, fmt.Errorf("deploy user is required")
	}
	if !validUserName(resolved.User) {
		return Options{}, fmt.Errorf("deploy user %q must contain only letters, digits, '.', '_', '-' or '$' and must start with a letter or '_'", resolved.User)
	}
	if resolved.ConnectAs == "" {
		resolved.ConnectAs = strings.TrimSpace(cfg.Server.SSHUser)
	}
	if resolved.ConnectAs == "" {
		return Options{}, fmt.Errorf("connection user is required")
	}
	if resolved.SudoMode == "" {
		resolved.SudoMode = strings.ToLower(strings.TrimSpace(cfg.HostHardening.SudoMode))
	}
	if resolved.SudoMode == "" {
		resolved.SudoMode = config.SudoModeLimited
	}
	switch resolved.SudoMode {
	case config.SudoModeLimited, config.SudoModeFull, config.SudoModeManual:
	default:
		return Options{}, fmt.Errorf("sudo mode must be one of: %s, %s, %s", config.SudoModeLimited, config.SudoModeFull, config.SudoModeManual)
	}

	publicKeyPath, publicKey, err := loadPublicKey(cfg, opts.PublicKeyPath)
	if err != nil {
		return Options{}, err
	}
	resolved.PublicKeyPath = publicKeyPath
	resolved.PublicKey = publicKey
	return resolved, nil
}

func validUserName(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		valid := r == '_' || r == '-' || r == '$' || r == '.' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9')
		if !valid {
			return false
		}
		if i == 0 && r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

func RiskReport(opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Deploy user sudo risk profile: %s\n", opts.SudoMode)
	switch opts.SudoMode {
	case config.SudoModeFull:
		b.WriteString("- grants NOPASSWD:ALL to the deploy user\n")
		b.WriteString("- equivalent to passwordless root escalation for that account\n")
		b.WriteString("- requires explicit --accept-sudo-all-risk before execution\n")
	case config.SudoModeManual:
		b.WriteString("- does not modify /etc/sudoers.d\n")
		b.WriteString("- prints manual sudoers instructions for operator review\n")
		b.WriteString("- deploy-user check will fail until sudoers is configured manually\n")
	default:
		b.WriteString("- writes a ResistanceStack-managed sudoers profile with a command allowlist\n")
		b.WriteString("- validates the sudoers file with visudo before completing\n")
		b.WriteString("- avoids broad NOPASSWD:ALL while preparing a limited-sudo path\n")
	}
	return b.String()
}

func sudoersContent(opts Options) string {
	switch opts.SudoMode {
	case config.SudoModeFull:
		return fmt.Sprintf(`# Managed by ResistanceStack deploy-user bootstrap.
%s ALL=(ALL) NOPASSWD:ALL`, opts.User)
	default:
		return fmt.Sprintf(`# Managed by ResistanceStack deploy-user bootstrap.
Cmnd_Alias RESISTACK_DEPLOY = /usr/bin/apt-get, /usr/bin/cat, /usr/bin/chmod, /usr/bin/cp, /usr/bin/find, /usr/bin/grep, /usr/bin/id, /usr/bin/install, /usr/bin/ln, /usr/bin/mv, /usr/bin/openssl, /usr/bin/python3, /usr/bin/rm, /usr/bin/sed, /usr/bin/systemctl, /usr/bin/tee, /usr/bin/test, /usr/bin/touch, /usr/bin/true, /bin/true, /usr/sbin/certbot, /usr/bin/certbot, /usr/sbin/service, /usr/sbin/sshd, /usr/sbin/ufw, /usr/sbin/useradd, /usr/sbin/usermod
%s ALL=(ALL) NOPASSWD: RESISTACK_DEPLOY`, opts.User)
	}
}

func DefaultPublicKeyPath(cfg config.Config) string {
	privateKeyPath := fsutil.ExpandHome(cfg.Server.PrivateKeyPath)
	if strings.TrimSpace(privateKeyPath) == "" {
		return ""
	}
	return privateKeyPath + ".pub"
}

func BuildCheckScript(opts Options) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

DEPLOY_USER=%s
EXPECTED_PUBLIC_KEY=%s

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

home_dir_for_user() {
  getent_field "$1" 6
}

primary_group_for_user() {
  id -gn "$1"
}

authorized_keys_path() {
  local home_dir
  home_dir="$(home_dir_for_user "$1")"
  printf '%%s/.ssh/authorized_keys\n' "${home_dir}"
}

check_passwordless_sudo() {
  if [ "$(id -un)" = "${DEPLOY_USER}" ]; then
    sudo -n -l >/dev/null 2>&1
    return 0
  fi
  sudo -n -u "${DEPLOY_USER}" sudo -n -l >/dev/null 2>&1
}

echo "[resistack] checking deploy user ${DEPLOY_USER}"

if ! getent passwd "${DEPLOY_USER}" >/dev/null 2>&1; then
  echo "[resistack] missing user: ${DEPLOY_USER}" >&2
  exit 1
fi
echo "[resistack] user exists"

if ! has_interactive_shell "${DEPLOY_USER}"; then
  echo "[resistack] non-interactive shell for ${DEPLOY_USER}" >&2
  exit 1
fi
echo "[resistack] login shell is interactive"

authorized_keys="$(authorized_keys_path "${DEPLOY_USER}")"
if ! sudo test -s "${authorized_keys}"; then
  echo "[resistack] authorized_keys missing or empty: ${authorized_keys}" >&2
  exit 1
fi
echo "[resistack] authorized_keys present: ${authorized_keys}"

if ! sudo grep -qxF "${EXPECTED_PUBLIC_KEY}" "${authorized_keys}"; then
  echo "[resistack] expected public key not installed for ${DEPLOY_USER}" >&2
  exit 1
fi
echo "[resistack] expected public key is installed"

if ! check_passwordless_sudo; then
  echo "[resistack] passwordless sudo missing for ${DEPLOY_USER}" >&2
  exit 1
fi
echo "[resistack] passwordless sudo is enabled"

echo "[resistack] deploy user is ready"
`, scriptutil.ShellQuote(opts.User), scriptutil.ShellQuote(opts.PublicKey))
}

func BuildBootstrapScript(opts Options) string {
	if opts.SudoMode == "" {
		opts.SudoMode = config.SudoModeLimited
	}
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

DEPLOY_USER=%s
EXPECTED_PUBLIC_KEY=%s
SUDO_MODE=%s
SUDOERS_CONTENT=%s

require_privileged_access() {
  if [ "$(id -u)" -eq 0 ]; then
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    echo "[resistack] sudo is required for deploy-user bootstrap" >&2
    exit 1
  fi
  if sudo -n true >/dev/null 2>&1; then
    return 0
  fi
  echo "[resistack] passwordless sudo is required for deploy-user bootstrap" >&2
  exit 1
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

home_dir_for_user() {
  getent_field "$1" 6
}

primary_group_for_user() {
  id -gn "$1"
}

authorized_keys_path() {
  local home_dir
  home_dir="$(home_dir_for_user "$1")"
  printf '%%s/.ssh/authorized_keys\n' "${home_dir}"
}

ensure_user_exists() {
  if getent passwd "${DEPLOY_USER}" >/dev/null 2>&1; then
    echo "[resistack] user already exists: ${DEPLOY_USER}"
    return 0
  fi
  echo "[resistack] creating user ${DEPLOY_USER}"
  sudo useradd --create-home --shell /bin/bash "${DEPLOY_USER}"
}

ensure_interactive_shell() {
  if has_interactive_shell "${DEPLOY_USER}"; then
    return 0
  fi
  echo "[resistack] setting interactive shell for ${DEPLOY_USER}"
  sudo usermod --shell /bin/bash "${DEPLOY_USER}"
}

ensure_authorized_key() {
  local home_dir
  local primary_group
  local ssh_dir
  local authorized_keys
  local tmp

  home_dir="$(home_dir_for_user "${DEPLOY_USER}")"
  primary_group="$(primary_group_for_user "${DEPLOY_USER}")"
  ssh_dir="${home_dir}/.ssh"
  authorized_keys="${ssh_dir}/authorized_keys"

  sudo install -d -m 0700 -o "${DEPLOY_USER}" -g "${primary_group}" "${ssh_dir}"

  tmp="$(mktemp)"
  trap 'rm -f "${tmp}"' RETURN
  sudo cat "${authorized_keys}" 2>/dev/null > "${tmp}" || true
  if grep -qxF "${EXPECTED_PUBLIC_KEY}" "${tmp}"; then
    echo "[resistack] public key already installed for ${DEPLOY_USER}"
    return 0
  fi
  printf '%%s\n' "${EXPECTED_PUBLIC_KEY}" >> "${tmp}"
  sudo install -m 0600 -o "${DEPLOY_USER}" -g "${primary_group}" "${tmp}" "${authorized_keys}"
  echo "[resistack] installed public key for ${DEPLOY_USER}"
}

ensure_passwordless_sudo() {
  local sudoers_path
  local tmp
  local current

  sudoers_path="/etc/sudoers.d/resistack-${DEPLOY_USER}"

  if [ "${SUDO_MODE}" = "manual" ]; then
    echo "[resistack] sudo_mode=manual; not modifying ${sudoers_path}"
    echo "[resistack] review and install a sudoers profile manually, then validate it with: sudo visudo -cf ${sudoers_path}"
    echo "[resistack] suggested sudoers content:"
    printf '%%s\n' "${SUDOERS_CONTENT}"
    return 0
  fi

  tmp="$(mktemp)"
  current="$(mktemp)"
  trap 'rm -f "${tmp}" "${current}"' RETURN
  printf '%%s\n' "${SUDOERS_CONTENT}" > "${tmp}"
  sudo visudo -cf "${tmp}" >/dev/null
  sudo cat "${sudoers_path}" > "${current}" 2>/dev/null || true
  if cmp -s "${tmp}" "${current}"; then
    echo "[resistack] passwordless sudo already configured for ${DEPLOY_USER} with mode ${SUDO_MODE}"
    return 0
  fi
  sudo install -m 0440 "${tmp}" "${sudoers_path}"
  sudo visudo -cf "${sudoers_path}" >/dev/null
  echo "[resistack] configured passwordless sudo for ${DEPLOY_USER} with mode ${SUDO_MODE}"
}

check_passwordless_sudo() {
  if [ "${SUDO_MODE}" = "manual" ]; then
    echo "[resistack] skipping passwordless sudo verification because sudo_mode=manual"
    return 0
  fi
  if [ "$(id -un)" = "${DEPLOY_USER}" ]; then
    sudo -n -l >/dev/null 2>&1
    return 0
  fi
  sudo -n -u "${DEPLOY_USER}" sudo -n -l >/dev/null 2>&1
}

verify_bootstrap() {
  local authorized_keys

  if ! getent passwd "${DEPLOY_USER}" >/dev/null 2>&1; then
    echo "[resistack] bootstrap verification failed: user missing" >&2
    exit 1
  fi
  if ! has_interactive_shell "${DEPLOY_USER}"; then
    echo "[resistack] bootstrap verification failed: non-interactive shell" >&2
    exit 1
  fi
  authorized_keys="$(authorized_keys_path "${DEPLOY_USER}")"
  if ! sudo grep -qxF "${EXPECTED_PUBLIC_KEY}" "${authorized_keys}"; then
    echo "[resistack] bootstrap verification failed: public key missing" >&2
    exit 1
  fi
  if ! check_passwordless_sudo; then
    echo "[resistack] bootstrap verification failed: passwordless sudo missing" >&2
    exit 1
  fi
}

require_privileged_access
ensure_user_exists
ensure_interactive_shell
ensure_authorized_key
ensure_passwordless_sudo
verify_bootstrap
echo "[resistack] deploy user bootstrap complete"
`, scriptutil.ShellQuote(opts.User), scriptutil.ShellQuote(opts.PublicKey), scriptutil.ShellQuote(opts.SudoMode), scriptutil.ShellQuote(sudoersContent(opts)))
}

func loadPublicKey(cfg config.Config, override string) (string, string, error) {
	path := strings.TrimSpace(override)
	if path == "" {
		path = DefaultPublicKeyPath(cfg)
	}
	path = fsutil.ExpandHome(path)
	if path == "" {
		return "", "", fmt.Errorf("public key path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read public key %s: %w", path, err)
	}
	publicKey := strings.TrimSpace(string(data))
	if publicKey == "" {
		return "", "", fmt.Errorf("public key file %s is empty", path)
	}
	return path, publicKey, nil
}

func targetForUser(cfg config.Config, user string) remote.Target {
	target := remote.NewTarget(cfg)
	target.User = user
	return target
}

func LocalPublicKeyPath(root string, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}
