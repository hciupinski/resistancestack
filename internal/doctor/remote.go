package doctor

import (
	"fmt"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
)

type remotePayload struct {
	OS             string `json:"os"`
	Bash           bool   `json:"bash"`
	Python3        bool   `json:"python3"`
	Sudo           bool   `json:"sudo"`
	Systemctl      bool   `json:"systemctl"`
	SystemdRunning bool   `json:"systemd_running"`
	AptGet         bool   `json:"apt_get"`
	SSHD           bool   `json:"sshd"`
	UFW            bool   `json:"ufw"`
	Fail2ban       bool   `json:"fail2ban"`
	Certbot        bool   `json:"certbot"`
	Docker         bool   `json:"docker"`
}

func buildRemoteScript(cfg config.Config) string {
	_ = cfg
	return `set -eu
os="unknown"
if [ -r /etc/os-release ]; then
  os="$(. /etc/os-release && printf '%s %s' "${NAME:-unknown}" "${VERSION_ID:-}")"
fi
json_bool() {
  if "$@" >/dev/null 2>&1; then printf true; else printf false; fi
}
systemd_running=false
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemd_running=true
fi
sshd_present=false
if command -v sshd >/dev/null 2>&1 || systemctl list-unit-files ssh.service sshd.service >/dev/null 2>&1; then
  sshd_present=true
fi
fail2ban_present=false
if command -v fail2ban-client >/dev/null 2>&1 || systemctl list-unit-files fail2ban.service >/dev/null 2>&1; then
  fail2ban_present=true
fi
printf '{'
printf '"os":%s,' "$(python3 - <<'PY' "$os" 2>/dev/null || printf '"unknown"'
import json, sys
print(json.dumps(sys.argv[1]))
PY
)"
printf '"bash":%s,' "$(json_bool command -v bash)"
printf '"python3":%s,' "$(json_bool command -v python3)"
printf '"sudo":%s,' "$(json_bool command -v sudo)"
printf '"systemctl":%s,' "$(json_bool command -v systemctl)"
printf '"systemd_running":%s,' "$systemd_running"
printf '"apt_get":%s,' "$(json_bool command -v apt-get)"
printf '"sshd":%s,' "$sshd_present"
printf '"ufw":%s,' "$(json_bool command -v ufw)"
printf '"fail2ban":%s,' "$fail2ban_present"
printf '"certbot":%s,' "$(json_bool command -v certbot)"
printf '"docker":%s' "$(json_bool command -v docker)"
printf '}'
`
}

func remoteChecksFromPayload(cfg config.Config, payload remotePayload) []Check {
	checks := []Check{}
	add := func(id string, status string, description string, detected string, recommendation string) {
		checks = append(checks, Check{
			Area:           ModeRemote,
			ID:             id,
			Status:         status,
			Description:    description,
			DetectedValue:  detected,
			Recommendation: recommendation,
		})
	}

	if strings.TrimSpace(payload.OS) == "" || payload.OS == "unknown" {
		add("remote.os", StatusWarn, "Remote operating system can be identified.", "unknown", "Verify the VPS OS manually; Ubuntu/Debian with systemd and apt-get is expected.")
	} else {
		add("remote.os", StatusPass, "Remote operating system can be identified.", payload.OS, "")
	}
	binaryCheck := func(id string, present bool, description string, install string, required bool) {
		status := StatusPass
		detected := "present"
		recommendation := ""
		if !present {
			detected = "missing"
			recommendation = install
			if required {
				status = StatusFail
			} else {
				status = StatusWarn
			}
		}
		add(id, status, description, detected, recommendation)
	}

	binaryCheck("remote.bash", payload.Bash, "bash is available on the remote host.", "Install bash with `sudo apt-get update && sudo apt-get install -y bash`.", true)
	binaryCheck("remote.python3", payload.Python3, "python3 is available on the remote host.", "Install python3 with `sudo apt-get update && sudo apt-get install -y python3`.", true)
	binaryCheck("remote.sudo", payload.Sudo, "sudo is available on the remote host.", "Install sudo and ensure the configured SSH user can run `sudo -n true`.", true)
	binaryCheck("remote.apt_get", payload.AptGet, "apt-get is available on the remote host.", "Use a Debian/Ubuntu host or install apt tooling before using host-hardening.", true)
	binaryCheck("remote.sshd", payload.SSHD, "sshd service is present on the remote host.", "Install OpenSSH server with `sudo apt-get install -y openssh-server`.", true)

	systemdOK := payload.Systemctl && payload.SystemdRunning
	systemdDetected := fmt.Sprintf("systemctl=%t systemd_running=%t", payload.Systemctl, payload.SystemdRunning)
	if systemdOK {
		add("remote.systemd", StatusPass, "systemd is available and running on the remote host.", systemdDetected, "")
	} else {
		add("remote.systemd", StatusFail, "systemd is available and running on the remote host.", systemdDetected, "Use a systemd-based VPS before applying host-hardening.")
	}

	binaryCheck("remote.ufw", payload.UFW, "ufw is available on the remote host.", "Install ufw with `sudo apt-get update && sudo apt-get install -y ufw`.", false)
	binaryCheck("remote.fail2ban", payload.Fail2ban, "fail2ban is available on the remote host.", "Install fail2ban with `sudo apt-get update && sudo apt-get install -y fail2ban`.", false)
	certbotRequired := cfg.HostHardening.SSLCertificates.Enabled && cfg.HostHardening.SSLCertificates.AutoIssue
	binaryCheck("remote.certbot", payload.Certbot, "certbot is available when managed certificate issuance is enabled.", "Install certbot with `sudo apt-get update && sudo apt-get install -y certbot`.", certbotRequired)
	binaryCheck("remote.docker", payload.Docker, "Docker CLI is available when this host runs containers.", "Install Docker if this deployment uses containers; otherwise this warning can be ignored.", false)

	return checks
}
