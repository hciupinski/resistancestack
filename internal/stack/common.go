package stack

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

type LocalArtifacts struct {
	ComposePath string
	ComposeRaw  []byte
	EnvPath     string
	EnvRaw      []byte
}

func newTarget(cfg config.Config) remote.Target {
	return remote.Target{
		Host:            cfg.Server.Host,
		User:            cfg.Server.SSHUser,
		Port:            cfg.Server.SSHPort,
		KeyPath:         cfg.Server.PrivateKeyPath,
		HostKeyChecking: cfg.Server.HostKeyChecking,
		KnownHostsPath:  cfg.Server.KnownHostsPath,
	}
}

func resolveArtifacts(cfg config.Config, wd string) (LocalArtifacts, error) {
	composePath := cfg.App.ComposeFile
	if !filepath.IsAbs(composePath) {
		composePath = filepath.Join(wd, composePath)
	}
	composeRaw, err := os.ReadFile(composePath)
	if err != nil {
		return LocalArtifacts{}, fmt.Errorf("read compose file: %w", err)
	}

	artifacts := LocalArtifacts{
		ComposePath: composePath,
		ComposeRaw:  composeRaw,
	}

	if envFile := strings.TrimSpace(cfg.App.EnvFile); envFile != "" {
		envPath := envFile
		if !filepath.IsAbs(envPath) {
			envPath = filepath.Join(wd, envPath)
		}
		envRaw, err := os.ReadFile(envPath)
		if err != nil {
			return LocalArtifacts{}, fmt.Errorf("read env file: %w", err)
		}
		artifacts.EnvPath = envPath
		artifacts.EnvRaw = envRaw
	}

	return artifacts, nil
}

func printWarnings(out io.Writer, warnings []string) {
	for _, warning := range warnings {
		fmt.Fprintf(out, "warning: %s\n", warning)
	}
}

func printErrors(out io.Writer, prefix string, errs []error) {
	for _, err := range errs {
		fmt.Fprintf(out, "%s: %v\n", prefix, err)
	}
}

func newReleaseID() string {
	return time.Now().UTC().Format("20060102150405")
}

func generateSecret() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func shellQuote(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
