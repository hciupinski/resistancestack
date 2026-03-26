package remote

import "github.com/hciupinski/resistancestack/internal/config"

func NewTarget(cfg config.Config) Target {
	return Target{
		Host:            cfg.Server.Host,
		User:            cfg.Server.SSHUser,
		Port:            cfg.Server.SSHPort,
		KeyPath:         cfg.Server.PrivateKeyPath,
		HostKeyChecking: cfg.Server.HostKeyChecking,
		KnownHostsPath:  cfg.Server.KnownHostsPath,
	}
}
