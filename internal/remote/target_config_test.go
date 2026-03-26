package remote

import (
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestNewTarget(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.Host = "example.com"
	cfg.Server.SSHUser = "ops"
	cfg.Server.SSHPort = 2222
	cfg.Server.PrivateKeyPath = "~/.ssh/custom"
	cfg.Server.HostKeyChecking = "accept-new"
	cfg.Server.KnownHostsPath = "~/.ssh/custom_known_hosts"

	target := NewTarget(cfg)
	if target.Host != cfg.Server.Host ||
		target.User != cfg.Server.SSHUser ||
		target.Port != cfg.Server.SSHPort ||
		target.KeyPath != cfg.Server.PrivateKeyPath ||
		target.HostKeyChecking != cfg.Server.HostKeyChecking ||
		target.KnownHostsPath != cfg.Server.KnownHostsPath {
		t.Fatalf("unexpected target %+v", target)
	}
}
