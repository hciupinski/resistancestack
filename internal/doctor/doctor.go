package doctor

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/fsutil"
	"github.com/hciupinski/resistancestack/internal/remote"
)

func Run(cfg config.Config, root string, opts Options) (Report, error) {
	mode := normalizeMode(opts.Mode)
	report := Report{
		GeneratedAt: time.Now().UTC(),
		Mode:        mode,
	}

	if mode == ModeLocal || mode == ModeAll {
		report.Checks = append(report.Checks, CheckLocal(cfg, root, opts.Version)...)
	}
	if mode == ModeRemote || mode == ModeAll {
		checks, err := CheckRemote(cfg)
		if err != nil {
			checks = append(checks, Check{
				Area:           ModeRemote,
				ID:             "remote.ssh.connection",
				Status:         StatusFail,
				Description:    "SSH connection to the target host failed.",
				DetectedValue:  err.Error(),
				Recommendation: "Verify server.host, server.ssh_user, server.ssh_port, server.private_key_path, known_hosts, and network reachability.",
			})
		}
		report.Checks = append(report.Checks, checks...)
	}

	report.Status = summarize(report.Checks)
	return report, nil
}

func CheckLocal(cfg config.Config, root string, version string) []Check {
	if strings.TrimSpace(version) == "" {
		version = "dev"
	}
	checks := []Check{{
		Area:           ModeLocal,
		ID:             "local.binary.version",
		Status:         StatusPass,
		Description:    "ResistanceStack binary version is available.",
		DetectedValue:  version,
		Recommendation: "",
	}}

	if path, err := exec.LookPath("ssh"); err != nil {
		checks = append(checks, Check{
			Area:           ModeLocal,
			ID:             "local.ssh.binary",
			Status:         StatusFail,
			Description:    "OpenSSH client is available locally.",
			DetectedValue:  "not found in PATH",
			Recommendation: "Install OpenSSH client, for example `sudo apt-get install openssh-client` or `brew install openssh`.",
		})
	} else {
		checks = append(checks, Check{
			Area:          ModeLocal,
			ID:            "local.ssh.binary",
			Status:        StatusPass,
			Description:   "OpenSSH client is available locally.",
			DetectedValue: path,
		})
	}

	keyPath := fsutil.ExpandHome(cfg.Server.PrivateKeyPath)
	switch {
	case strings.TrimSpace(keyPath) == "":
		checks = append(checks, Check{
			Area:           ModeLocal,
			ID:             "local.ssh.private_key",
			Status:         StatusFail,
			Description:    "Configured private key exists locally.",
			DetectedValue:  "server.private_key_path is empty",
			Recommendation: "Set `server.private_key_path` to the SSH private key used for the VPS.",
		})
	default:
		info, err := os.Stat(keyPath)
		if err != nil {
			checks = append(checks, Check{
				Area:           ModeLocal,
				ID:             "local.ssh.private_key",
				Status:         StatusFail,
				Description:    "Configured private key exists locally.",
				DetectedValue:  keyPath,
				Recommendation: fmt.Sprintf("Create or copy the key to `%s`, then set permissions with `chmod 600 %s`.", keyPath, keyPath),
			})
		} else if info.IsDir() {
			checks = append(checks, Check{
				Area:           ModeLocal,
				ID:             "local.ssh.private_key",
				Status:         StatusFail,
				Description:    "Configured private key exists locally.",
				DetectedValue:  keyPath + " is a directory",
				Recommendation: "Set `server.private_key_path` to a private key file.",
			})
		} else if info.Mode().Perm()&0o077 != 0 {
			checks = append(checks, Check{
				Area:           ModeLocal,
				ID:             "local.ssh.private_key",
				Status:         StatusWarn,
				Description:    "Configured private key permissions are restricted.",
				DetectedValue:  fmt.Sprintf("%s mode %04o", keyPath, info.Mode().Perm()),
				Recommendation: fmt.Sprintf("Run `chmod 600 %s`.", keyPath),
			})
		} else {
			checks = append(checks, Check{
				Area:          ModeLocal,
				ID:            "local.ssh.private_key",
				Status:        StatusPass,
				Description:   "Configured private key exists locally.",
				DetectedValue: keyPath,
			})
		}
	}

	if strings.EqualFold(strings.TrimSpace(cfg.Server.HostKeyChecking), "strict") {
		knownHostsPath := fsutil.ExpandHome(cfg.Server.KnownHostsPath)
		if strings.TrimSpace(knownHostsPath) == "" {
			checks = append(checks, Check{
				Area:           ModeLocal,
				ID:             "local.ssh.known_hosts",
				Status:         StatusFail,
				Description:    "Known hosts file exists for strict SSH host key checking.",
				DetectedValue:  "server.known_hosts_path is empty",
				Recommendation: "Set `server.known_hosts_path` or switch `server.host_key_checking` to `accept-new` for first contact.",
			})
		} else if _, err := os.Stat(knownHostsPath); err != nil {
			checks = append(checks, Check{
				Area:           ModeLocal,
				ID:             "local.ssh.known_hosts",
				Status:         StatusFail,
				Description:    "Known hosts file exists for strict SSH host key checking.",
				DetectedValue:  knownHostsPath,
				Recommendation: fmt.Sprintf("Run `ssh-keyscan -p %d %s >> %s` after verifying the host fingerprint.", cfg.Server.SSHPort, cfg.Server.Host, knownHostsPath),
			})
		} else {
			checks = append(checks, Check{
				Area:          ModeLocal,
				ID:            "local.ssh.known_hosts",
				Status:        StatusPass,
				Description:   "Known hosts file exists for strict SSH host key checking.",
				DetectedValue: knownHostsPath,
			})
		}
	} else {
		checks = append(checks, Check{
			Area:           ModeLocal,
			ID:             "local.ssh.known_hosts",
			Status:         StatusWarn,
			Description:    "Strict known_hosts verification is not enabled.",
			DetectedValue:  cfg.Server.HostKeyChecking,
			Recommendation: "Use `server.host_key_checking: strict` with a pinned `server.known_hosts_path` before production hardening.",
		})
	}

	checks = append(checks, checkOutputPath(root, cfg)...)
	return checks
}

func CheckRemote(cfg config.Config) ([]Check, error) {
	raw, err := remote.CaptureScript(remote.NewTarget(cfg), buildRemoteScript(cfg))
	if err != nil {
		return nil, err
	}

	var payload remotePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, fmt.Errorf("decode remote doctor report: %w", err)
	}
	return remoteChecksFromPayload(cfg, payload), nil
}

func checkOutputPath(root string, cfg config.Config) []Check {
	dir := cfg.Reporting.OutputPath
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return []Check{{
			Area:           ModeLocal,
			ID:             "local.reporting.output_path",
			Status:         StatusFail,
			Description:    "Report output path can be created.",
			DetectedValue:  dir,
			Recommendation: "Choose a writable `reporting.output_path` or fix directory permissions.",
		}}
	}
	probe, err := os.CreateTemp(dir, ".doctor-write-test-*")
	if err != nil {
		return []Check{{
			Area:           ModeLocal,
			ID:             "local.reporting.output_path",
			Status:         StatusFail,
			Description:    "Report output path is writable.",
			DetectedValue:  dir,
			Recommendation: "Choose a writable `reporting.output_path` or fix directory permissions.",
		}}
	}
	probeName := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(probeName)
	if closeErr != nil || removeErr != nil {
		return []Check{{
			Area:           ModeLocal,
			ID:             "local.reporting.output_path",
			Status:         StatusWarn,
			Description:    "Report output path cleanup works.",
			DetectedValue:  dir,
			Recommendation: "Check filesystem permissions for temporary report files.",
		}}
	}
	return []Check{{
		Area:          ModeLocal,
		ID:            "local.reporting.output_path",
		Status:        StatusPass,
		Description:   "Report output path is writable.",
		DetectedValue: dir,
	}}
}

func summarize(checks []Check) string {
	status := StatusPass
	for _, check := range checks {
		switch check.Status {
		case StatusFail:
			return StatusFail
		case StatusWarn:
			status = StatusWarn
		}
	}
	return status
}

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ModeLocal:
		return ModeLocal
	case ModeRemote:
		return ModeRemote
	default:
		return ModeAll
	}
}
