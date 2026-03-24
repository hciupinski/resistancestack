package preflight

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/fsutil"
)

func CheckLocal(cfg config.Config, requireSSH bool) (warnings []string, errs []error) {
	if requireSSH {
		if _, err := exec.LookPath("ssh"); err != nil {
			errs = append(errs, fmt.Errorf("ssh client not found in PATH"))
		}

		keyPath := fsutil.ExpandHome(cfg.Server.PrivateKeyPath)
		if keyPath == "" {
			errs = append(errs, fmt.Errorf("server.private_key_path is empty"))
		} else if _, err := os.Stat(keyPath); err != nil {
			errs = append(errs, fmt.Errorf("private key not found at %s", keyPath))
		}

		if strings.EqualFold(strings.TrimSpace(cfg.Server.HostKeyChecking), "strict") {
			knownHostsPath := fsutil.ExpandHome(cfg.Server.KnownHostsPath)
			if knownHostsPath == "" {
				errs = append(errs, fmt.Errorf("known hosts path is empty"))
			} else if _, err := os.Stat(knownHostsPath); err != nil {
				errs = append(errs, fmt.Errorf("known hosts file not found at %s", knownHostsPath))
			}
		}
	}

	if cfg.CI.GenerateWorkflows && strings.TrimSpace(cfg.CI.Provider) == "" {
		errs = append(errs, fmt.Errorf("ci.provider must be set when ci.generate_workflows=true"))
	}
	if cfg.Observability.Enable && strings.TrimSpace(cfg.Observability.LocalDataDir) == "" {
		errs = append(errs, fmt.Errorf("observability.local_data_dir is required when observability.enable=true"))
	}
	if cfg.Alerts.Enabled && strings.TrimSpace(cfg.Alerts.WebhookURL) == "" && strings.TrimSpace(cfg.Alerts.Email) == "" && strings.TrimSpace(cfg.Alerts.SlackURL) == "" {
		warnings = append(warnings, "alerts are enabled but no delivery destination is configured")
	}

	return warnings, errs
}
