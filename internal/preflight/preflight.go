package preflight

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/fsutil"
)

func CheckLocal(cfg config.Config, wd string, requireSSH bool) (warnings []string, errs []error) {
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
			} else if hostKnown, err := hostPresentInKnownHosts(cfg, knownHostsPath); err != nil {
				errs = append(errs, err)
			} else if !hostKnown {
				errs = append(errs, fmt.Errorf("host %s is not present in %s; add it before deploy or switch to accept-new", knownHostsLookup(cfg), knownHostsPath))
			}
		}
	}

	composePath := cfg.App.ComposeFile
	if !filepath.IsAbs(composePath) {
		composePath = filepath.Join(wd, composePath)
	}
	rawCompose, err := os.ReadFile(composePath)
	if err != nil {
		errs = append(errs, fmt.Errorf("compose file not found at %s", composePath))
	} else if composeUsesBuildContext(string(rawCompose)) {
		errs = append(errs, fmt.Errorf("compose file at %s uses build contexts; remote deploy currently supports prebuilt images only", composePath))
	}

	if envFile := strings.TrimSpace(cfg.App.EnvFile); envFile != "" {
		envPath := envFile
		if !filepath.IsAbs(envPath) {
			envPath = filepath.Join(wd, envPath)
		}
		if _, err := os.Stat(envPath); err != nil {
			errs = append(errs, fmt.Errorf("env file not found at %s", envPath))
		}
	}

	if cfg.Alerts.Enabled && strings.TrimSpace(cfg.Alerts.WebhookURL) == "" {
		warnings = append(warnings, "alerts are enabled but webhook url is empty")
	}

	return warnings, errs
}

func composeUsesBuildContext(raw string) bool {
	buildPattern := regexp.MustCompile(`(?m)^[[:space:]]*build[[:space:]]*:`)
	return buildPattern.MatchString(raw)
}

func hostPresentInKnownHosts(cfg config.Config, knownHostsPath string) (bool, error) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return false, fmt.Errorf("ssh-keygen not found in PATH; cannot validate known hosts")
	}

	cmd := exec.Command("ssh-keygen", "-F", knownHostsLookup(cfg), "-f", knownHostsPath)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("check known hosts: %w", err)
	}
	return true, nil
}

func knownHostsLookup(cfg config.Config) string {
	if cfg.Server.SSHPort == 22 {
		return cfg.Server.Host
	}
	return fmt.Sprintf("[%s]:%d", cfg.Server.Host, cfg.Server.SSHPort)
}
