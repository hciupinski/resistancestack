package deploy

import (
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestBuildProvisionScript_UsesAllowlistRules(t *testing.T) {
	cfg := config.Default("myproj")
	cfg.Security.AdminAllowlist = []string{"10.0.0.1/32", "192.168.1.0/24"}
	release := NewRelease(cfg.ProjectName, "20260308120000")

	script := BuildProvisionScript(cfg, release)

	if !strings.Contains(script, "sudo ufw allow from 10.0.0.1/32 to any port 22 proto tcp") {
		t.Fatal("expected first allowlist SSH rule in script")
	}
	if !strings.Contains(script, "sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp") {
		t.Fatal("expected second allowlist SSH rule in script")
	}
}

func TestBuildProvisionScript_FallsBackToOpenSSHPort(t *testing.T) {
	cfg := config.Default("myproj")
	cfg.Security.AdminAllowlist = nil
	release := NewRelease(cfg.ProjectName, "20260308120000")

	script := BuildProvisionScript(cfg, release)
	if !strings.Contains(script, "sudo ufw allow 22/tcp") {
		t.Fatal("expected open SSH fallback rule")
	}
}

func TestBuildProvisionScript_ConfiguresNginxAndWebhook(t *testing.T) {
	cfg := config.Default("myproj")
	release := NewRelease(cfg.ProjectName, "20260308120000")

	script := BuildProvisionScript(cfg, release)
	if !strings.Contains(script, "/etc/nginx/sites-available/resistack-${PROJECT}.conf") {
		t.Fatal("expected nginx site configuration")
	}
	if !strings.Contains(script, "location /_resistack/status/") {
		t.Fatal("expected dashboard location in nginx config")
	}
	if !strings.Contains(script, "/usr/local/bin/resistack-f2b-webhook") {
		t.Fatal("expected fail2ban webhook script")
	}
	if !strings.Contains(script, "certbot_args=(certonly --webroot") {
		t.Fatal("expected certbot webroot issuance flow")
	}
	if !strings.Contains(script, "listen 443 ssl http2;") {
		t.Fatal("expected nginx TLS server block")
	}
	if !strings.Contains(script, "APP_COMPOSE_ARGS=(--project-name \"${PROJECT}-app\"") {
		t.Fatal("expected app compose deployment flow")
	}
	if !strings.Contains(script, "sudo htpasswd -bcB") {
		t.Fatal("expected dashboard basic auth provisioning")
	}
}
