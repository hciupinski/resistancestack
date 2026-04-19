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
	User          string
	ConnectAs     string
	PublicKey     string
	PublicKeyPath string
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
	if dryRun {
		fmt.Fprintf(out, "Deploy user bootstrap plan:\n- connect as: %s\n- deploy user: %s\n- public key: %s\n", resolved.ConnectAs, resolved.User, resolved.PublicKeyPath)
		fmt.Fprintln(out, "Generated deploy-user bootstrap script:")
		fmt.Fprintln(out, BuildBootstrapScript(resolved))
		return nil
	}
	target := targetForUser(cfg, resolved.ConnectAs)
	return remote.RunScript(target, BuildBootstrapScript(resolved), out, errOut)
}

func ResolveOptions(cfg config.Config, opts Options) (Options, error) {
	resolved := Options{
		User:      strings.TrimSpace(opts.User),
		ConnectAs: strings.TrimSpace(opts.ConnectAs),
	}
	if resolved.User == "" {
		resolved.User = config.PreferredDeployUser(cfg)
	}
	if resolved.User == "" {
		return Options{}, fmt.Errorf("deploy user is required")
	}
	if strings.ContainsAny(resolved.User, " \t\r\n") {
		return Options{}, fmt.Errorf("deploy user %q must not contain whitespace", resolved.User)
	}
	if resolved.ConnectAs == "" {
		resolved.ConnectAs = strings.TrimSpace(cfg.Server.SSHUser)
	}
	if resolved.ConnectAs == "" {
		return Options{}, fmt.Errorf("connection user is required")
	}

	publicKeyPath, publicKey, err := loadPublicKey(cfg, opts.PublicKeyPath)
	if err != nil {
		return Options{}, err
	}
	resolved.PublicKeyPath = publicKeyPath
	resolved.PublicKey = publicKey
	return resolved, nil
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
    sudo -n true >/dev/null 2>&1
    return 0
  fi
  sudo -n -u "${DEPLOY_USER}" sudo -n true >/dev/null 2>&1
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
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

DEPLOY_USER=%s
EXPECTED_PUBLIC_KEY=%s

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
  sudoers_path="/etc/sudoers.d/resistack-${DEPLOY_USER}"
  if sudo test -f "${sudoers_path}" && sudo grep -qxF "${DEPLOY_USER} ALL=(ALL) NOPASSWD:ALL" "${sudoers_path}"; then
    echo "[resistack] passwordless sudo already configured for ${DEPLOY_USER}"
    return 0
  fi
  printf '%%s\n' "${DEPLOY_USER} ALL=(ALL) NOPASSWD:ALL" | sudo tee "${sudoers_path}" >/dev/null
  sudo chmod 440 "${sudoers_path}"
  echo "[resistack] enabled passwordless sudo for ${DEPLOY_USER}"
}

check_passwordless_sudo() {
  if [ "$(id -un)" = "${DEPLOY_USER}" ]; then
    sudo -n true >/dev/null 2>&1
    return 0
  fi
  sudo -n -u "${DEPLOY_USER}" sudo -n true >/dev/null 2>&1
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
`, scriptutil.ShellQuote(opts.User), scriptutil.ShellQuote(opts.PublicKey))
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
