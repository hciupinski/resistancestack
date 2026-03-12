package deploy

import (
	"fmt"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
)

type Release struct {
	ID                string
	RemoteRoot        string
	RemoteReleaseDir  string
	RemoteComposePath string
	RemoteEnvPath     string
}

type ProfileSettings struct {
	MaxRetry       int
	BanTime        string
	RecidiveBan    string
	LoginGraceTime int
}

func NewRelease(projectName string, releaseID string) Release {
	root := "/opt/resistack/" + projectName
	releaseDir := root + "/releases/" + releaseID
	return Release{
		ID:                releaseID,
		RemoteRoot:        root,
		RemoteReleaseDir:  releaseDir,
		RemoteComposePath: releaseDir + "/docker-compose.app.yml",
		RemoteEnvPath:     releaseDir + "/.env.app",
	}
}

func BuildProvisionScript(cfg config.Config, release Release) string {
	profile := resolveProfile(cfg.Security.Profile)
	webhookValue := strings.TrimSpace(cfg.Alerts.WebhookURL)
	if webhookValue == "" {
		webhookValue = "disabled"
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

PROJECT=%s
ROOT_DIR=%s
RELEASE_DIR=%s
APP_COMPOSE_PATH=%s
APP_ENV_PATH=%s
FQDN=%s
APP_UPSTREAM=%s
TLS_ENABLED=%s
LETSENCRYPT_EMAIL=%s
LETSENCRYPT_STAGING=%s
WEBHOOK_URL=%s
DASHBOARD_PATH=%s
DASHBOARD_BASIC_AUTH_ENABLED=%s
DASHBOARD_USERNAME=%s
DASHBOARD_PASSWORD=%s

echo "[resistack] starting provisioning for ${PROJECT}"

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required on target host"
  exit 1
fi

if ! sudo -n true 2>/dev/null; then
  echo "passwordless sudo is required for automated provisioning"
  exit 1
fi

if [ ! -f "${APP_COMPOSE_PATH}" ]; then
  echo "application compose file not found at ${APP_COMPOSE_PATH}"
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y docker.io docker-compose-plugin ufw fail2ban curl ca-certificates nginx certbot python3-certbot-nginx apache2-utils
else
  echo "Unsupported package manager. v1 currently supports apt-based systems."
  exit 1
fi

sudo systemctl enable --now docker
sudo systemctl enable --now fail2ban nginx

sudo install -d -m 0755 "${ROOT_DIR}" "${ROOT_DIR}/releases" "${ROOT_DIR}/shared"
sudo chown -R "${USER}":"${USER}" "${ROOT_DIR}"
sudo install -d -m 0755 /var/www/certbot /etc/nginx/conf.d

backup_file() {
  local path="$1"
  if [ -f "${path}" ]; then
    sudo cp -a "${path}" "${path}.resistack.bak"
  fi
}

current_client_ip() {
  printf '%%s' "${SSH_CONNECTION%% *}"
}

validate_current_client_ip() {
  local current_ip="$1"
  if [ -z "${current_ip}" ]; then
    return 0
  fi
  python3 - %s "${current_ip}" <<'PY'
import ipaddress
import sys

raw_allowlist = sys.argv[1]
current_ip = sys.argv[2]
allowlist = [entry.strip() for entry in raw_allowlist.split(",") if entry.strip()]
if not allowlist:
    sys.exit(0)

address = ipaddress.ip_address(current_ip)
if not any(address in ipaddress.ip_network(entry, strict=False) for entry in allowlist):
    print(f"current SSH client IP {current_ip} is not present in security.admin_allowlist", file=sys.stderr)
    sys.exit(1)
PY
}

sshd_cfg=/etc/ssh/sshd_config
ensure_sshd_option() {
  key="$1"
  value="$2"
  if sudo grep -qE "^[#[:space:]]*${key}[[:space:]]+" "${sshd_cfg}"; then
    sudo sed -i -E "s|^[#[:space:]]*${key}[[:space:]]+.*|${key} ${value}|g" "${sshd_cfg}"
  else
    echo "${key} ${value}" | sudo tee -a "${sshd_cfg}" >/dev/null
  fi
}

cat > /tmp/resistack-alerts.env <<EOF
WEBHOOK_URL=${WEBHOOK_URL}
EOF
sudo mv /tmp/resistack-alerts.env /etc/default/resistack-alerts
sudo chmod 0644 /etc/default/resistack-alerts

cat > /tmp/resistack-f2b-webhook.sh <<'ALERTSCRIPT'
#!/usr/bin/env bash
set -euo pipefail

if [ -f /etc/default/resistack-alerts ]; then
  # shellcheck source=/dev/null
  source /etc/default/resistack-alerts
fi

if [ -z "${WEBHOOK_URL:-}" ] || [ "${WEBHOOK_URL}" = "disabled" ]; then
  exit 0
fi

event="${1:-ban}"
jail="${2:-unknown}"
ip="${3:-unknown}"
host="$(hostname -f 2>/dev/null || hostname)"
timestamp="$(date -u +"%%Y-%%m-%%dT%%H:%%M:%%SZ")"
severity="high"
if [ "${event}" = "unban" ]; then
  severity="info"
fi

payload="{\"event_type\":\"fail2ban_${event}\",\"severity\":\"${severity}\",\"source\":\"fail2ban\",\"host\":\"${host}\",\"jail\":\"${jail}\",\"ip\":\"${ip}\",\"timestamp_utc\":\"${timestamp}\"}"
curl -fsS -m 8 -H "Content-Type: application/json" -d "${payload}" "${WEBHOOK_URL}" >/dev/null || true
ALERTSCRIPT
sudo mv /tmp/resistack-f2b-webhook.sh /usr/local/bin/resistack-f2b-webhook
sudo chmod 0755 /usr/local/bin/resistack-f2b-webhook

cat > /tmp/resistack-webhook-action.conf <<'ACTION'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = /usr/local/bin/resistack-f2b-webhook ban <name> <ip>
actionunban = /usr/local/bin/resistack-f2b-webhook unban <name> <ip>
ACTION
sudo mv /tmp/resistack-webhook-action.conf /etc/fail2ban/action.d/resistack-webhook.conf

cat > /tmp/resistack-jail.local <<'JAIL'
[DEFAULT]
bantime = %s
findtime = 10m
maxretry = %d
backend = systemd
banaction = ufw
action = %%(action_)s
         resistack-webhook

[sshd]
enabled = true
mode = aggressive

[recidive]
enabled = true
bantime = %s
findtime = 1d
maxretry = 5
JAIL
sudo mv /tmp/resistack-jail.local /etc/fail2ban/jail.d/resistack.local
sudo systemctl restart fail2ban

backup_file "${sshd_cfg}"
ensure_sshd_option "PermitRootLogin" "no"
ensure_sshd_option "PasswordAuthentication" "no"
ensure_sshd_option "PubkeyAuthentication" "yes"
ensure_sshd_option "MaxAuthTries" "%d"
ensure_sshd_option "LoginGraceTime" "%d"

if command -v sshd >/dev/null 2>&1; then
  sudo sshd -t
fi
if systemctl list-unit-files | grep -q '^ssh.service'; then
  sudo systemctl restart ssh
elif systemctl list-unit-files | grep -q '^sshd.service'; then
  sudo systemctl restart sshd
fi

validate_current_client_ip "$(current_client_ip)"

sudo ufw --force disable >/dev/null 2>&1 || true
sudo ufw default deny incoming
sudo ufw default allow outgoing
%s
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

cat > "${ROOT_DIR}/shared/docker-compose.security.yml" <<'COMPOSE'
services:
  uptime-kuma:
    image: louislam/uptime-kuma:1
    restart: unless-stopped
    ports:
      - "127.0.0.1:3001:3001"
    volumes:
      - ./uptime-kuma:/app/data
COMPOSE

pushd "${ROOT_DIR}/shared" >/dev/null
sudo docker compose --project-name "${PROJECT}-security" -f docker-compose.security.yml up -d
popd >/dev/null

PREVIOUS_RELEASE_DIR=""
if [ -L "${ROOT_DIR}/current" ]; then
  PREVIOUS_RELEASE_DIR="$(readlink -f "${ROOT_DIR}/current")"
fi

APP_COMPOSE_ARGS=(--project-name "${PROJECT}-app" -f "${APP_COMPOSE_PATH}")
if [ -n "${APP_ENV_PATH}" ] && [ -f "${APP_ENV_PATH}" ]; then
  APP_COMPOSE_ARGS+=(--env-file "${APP_ENV_PATH}")
fi

sudo docker compose "${APP_COMPOSE_ARGS[@]}" pull --ignore-pull-failures || true
if ! sudo docker compose "${APP_COMPOSE_ARGS[@]}" up -d --remove-orphans; then
  echo "application deploy failed"
  if [ -n "${PREVIOUS_RELEASE_DIR}" ] && [ -f "${PREVIOUS_RELEASE_DIR}/docker-compose.app.yml" ]; then
    PREV_ARGS=(--project-name "${PROJECT}-app" -f "${PREVIOUS_RELEASE_DIR}/docker-compose.app.yml")
    if [ -f "${PREVIOUS_RELEASE_DIR}/.env.app" ]; then
      PREV_ARGS+=(--env-file "${PREVIOUS_RELEASE_DIR}/.env.app")
    fi
    sudo docker compose "${PREV_ARGS[@]}" up -d --remove-orphans || true
  fi
  exit 1
fi
ln -sfn "${RELEASE_DIR}" "${ROOT_DIR}/current"

cat > /tmp/resistack-logformat.conf <<'LOGFORMAT'
log_format resistack '$time_iso8601\t$status\t$request_method\t$uri\t$remote_addr\t$http_user_agent';
LOGFORMAT
sudo mv /tmp/resistack-logformat.conf /etc/nginx/conf.d/resistack-logformat.conf

if [ "${DASHBOARD_BASIC_AUTH_ENABLED}" = "true" ]; then
  sudo htpasswd -bcB "/etc/nginx/resistack-${PROJECT}.htpasswd" "${DASHBOARD_USERNAME}" "${DASHBOARD_PASSWORD}" >/dev/null
fi

cat > /tmp/resistack-nginx.conf <<EOF
server {
    listen 80;
    server_name ${FQDN};
    access_log /var/log/nginx/resistack-access.log resistack;
    error_log /var/log/nginx/resistack-error.log warn;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

%s

    location / {
        proxy_pass ${APP_UPSTREAM};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
sudo mv /tmp/resistack-nginx.conf /etc/nginx/sites-available/resistack-${PROJECT}.conf
sudo ln -sfn /etc/nginx/sites-available/resistack-${PROJECT}.conf /etc/nginx/sites-enabled/resistack-${PROJECT}.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx

if [ "${TLS_ENABLED}" = "true" ]; then
  certbot_args=(certonly --webroot -w /var/www/certbot -d "${FQDN}" --email "${LETSENCRYPT_EMAIL}" --agree-tos --non-interactive --keep-until-expiring)
  if [ "${LETSENCRYPT_STAGING}" = "true" ]; then
    certbot_args+=(--test-cert)
  fi
  sudo certbot "${certbot_args[@]}"

  cat > /tmp/resistack-nginx.conf <<EOF
server {
    listen 80;
    server_name ${FQDN};
    access_log /var/log/nginx/resistack-access.log resistack;
    error_log /var/log/nginx/resistack-error.log warn;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name ${FQDN};
    access_log /var/log/nginx/resistack-access.log resistack;
    error_log /var/log/nginx/resistack-error.log warn;

    ssl_certificate /etc/letsencrypt/live/${FQDN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${FQDN}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

%s

    location / {
        proxy_pass ${APP_UPSTREAM};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
  sudo mv /tmp/resistack-nginx.conf /etc/nginx/sites-available/resistack-${PROJECT}.conf
  sudo nginx -t
  sudo systemctl reload nginx

  cat > /tmp/resistack-certbot-reload.sh <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail
systemctl reload nginx
HOOK
  sudo install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  sudo mv /tmp/resistack-certbot-reload.sh /etc/letsencrypt/renewal-hooks/deploy/resistack-nginx-reload.sh
  sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/resistack-nginx-reload.sh
fi

echo "[resistack] provisioning completed"
if [ "${TLS_ENABLED}" = "true" ]; then
  echo "[resistack] dashboard: https://${FQDN}${DASHBOARD_PATH}"
else
  echo "[resistack] dashboard: http://${FQDN}${DASHBOARD_PATH}"
fi
`, shellQuote(cfg.ProjectName),
		shellQuote(release.RemoteRoot),
		shellQuote(release.RemoteReleaseDir),
		shellQuote(release.RemoteComposePath),
		shellQuote(release.RemoteEnvPath),
		shellQuote(cfg.Domain.FQDN),
		shellQuote(cfg.App.UpstreamURL),
		shellQuote(boolString(cfg.TLS.Enabled)),
		shellQuote(defaultString(cfg.TLS.Email, "disabled")),
		shellQuote(boolString(cfg.TLS.Staging)),
		shellQuote(webhookValue),
		shellQuote(cfg.Dashboard.Path),
		shellQuote(boolString(cfg.Dashboard.BasicAuth.Enabled)),
		shellQuote(cfg.Dashboard.BasicAuth.Username),
		shellQuote(cfg.Dashboard.BasicAuth.Password),
		shellQuote(strings.Join(cfg.Security.AdminAllowlist, ",")),
		profile.BanTime,
		profile.MaxRetry,
		profile.RecidiveBan,
		profile.MaxRetry,
		profile.LoginGraceTime,
		buildSSHAllowRules(cfg.Security.AdminAllowlist),
		buildStatusLocation(cfg),
		buildStatusLocation(cfg))
}

func buildSSHAllowRules(allowlist []string) string {
	if len(allowlist) == 0 {
		return "sudo ufw allow 22/tcp"
	}

	lines := make([]string, 0, len(allowlist))
	for _, cidr := range allowlist {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("sudo ufw allow from %s to any port 22 proto tcp", cidr))
	}

	if len(lines) == 0 {
		return "sudo ufw allow 22/tcp"
	}
	return strings.Join(lines, "\n")
}

func buildStatusLocation(cfg config.Config) string {
	var lines []string
	lines = append(lines,
		fmt.Sprintf("    location %s {", cfg.Dashboard.Path),
	)
	for _, cidr := range cfg.Security.AdminAllowlist {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("        allow %s;", cidr))
	}
	if len(cfg.Security.AdminAllowlist) > 0 {
		lines = append(lines, "        deny all;")
	}
	if cfg.Dashboard.BasicAuth.Enabled {
		lines = append(lines,
			`        auth_basic "ResistanceStack Status";`,
			`        auth_basic_user_file /etc/nginx/resistack-${PROJECT}.htpasswd;`,
		)
	}
	lines = append(lines,
		"        proxy_pass http://127.0.0.1:3001/;",
		"        proxy_set_header Host $host;",
		"        proxy_set_header X-Real-IP $remote_addr;",
		"        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"        proxy_set_header X-Forwarded-Proto $scheme;",
		"    }",
	)
	return strings.Join(lines, "\n")
}

func resolveProfile(profile string) ProfileSettings {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "strict":
		return ProfileSettings{
			MaxRetry:       3,
			BanTime:        "7d",
			RecidiveBan:    "14d",
			LoginGraceTime: 20,
		}
	case "lenient":
		return ProfileSettings{
			MaxRetry:       8,
			BanTime:        "12h",
			RecidiveBan:    "3d",
			LoginGraceTime: 60,
		}
	default:
		return ProfileSettings{
			MaxRetry:       5,
			BanTime:        "24h",
			RecidiveBan:    "7d",
			LoginGraceTime: 30,
		}
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func defaultString(v string, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}

func shellQuote(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}
