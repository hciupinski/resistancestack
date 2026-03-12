package scaffold

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hciupinski/resistancestack/internal/ci"
	"github.com/hciupinski/resistancestack/internal/config"
)

type Options struct {
	Root        string
	ProjectName string
	ConfigPath  string
	Force       bool
	WithCI      bool
}

type Result struct {
	Written []string
	Skipped []string
}

func Generate(opts Options) (Result, error) {
	if strings.TrimSpace(opts.Root) == "" {
		return Result{}, fmt.Errorf("root path is required")
	}
	if strings.TrimSpace(opts.ProjectName) == "" {
		return Result{}, fmt.Errorf("project name is required")
	}
	if strings.TrimSpace(opts.ConfigPath) == "" {
		return Result{}, fmt.Errorf("config path is required")
	}

	result := Result{}
	if err := ensureConfig(opts, &result); err != nil {
		return Result{}, err
	}
	if err := ensureAppCompose(opts, &result); err != nil {
		return Result{}, err
	}
	if err := ensureEnvExample(opts, &result); err != nil {
		return Result{}, err
	}

	if opts.WithCI {
		workflowPath, created, err := ci.EnsureSecurityWorkflow(opts.Root)
		if err != nil {
			return Result{}, err
		}
		if created {
			result.Written = append(result.Written, workflowPath)
		} else {
			result.Skipped = append(result.Skipped, workflowPath)
		}
	}

	return result, nil
}

func ensureConfig(opts Options, result *Result) error {
	cfg := config.Default(opts.ProjectName)
	cfg.Domain.FQDN = "localhost"
	cfg.App.ComposeFile = "./docker-compose.app.yml"
	cfg.App.EnvFile = "./.env.app"
	cfg.App.UpstreamURL = "http://127.0.0.1:8080"
	cfg.App.HealthcheckURL = "http://127.0.0.1:8080/"
	cfg.TLS.Enabled = false
	cfg.TLS.Staging = true
	cfg.Server.HostKeyChecking = "accept-new"
	cfg.Security.AdminAllowlist = []string{}

	if _, err := os.Stat(opts.ConfigPath); err == nil && !opts.Force {
		result.Skipped = append(result.Skipped, opts.ConfigPath)
		return nil
	}
	if err := config.Save(opts.ConfigPath, cfg); err != nil {
		return err
	}
	result.Written = append(result.Written, opts.ConfigPath)
	return nil
}

func ensureAppCompose(opts Options, result *Result) error {
	path := filepath.Join(opts.Root, "docker-compose.app.yml")
	content := `services:
  app:
    image: nginx:alpine
    container_name: ` + opts.ProjectName + `-app
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:80"
`
	return writeOrSkip(path, []byte(content), 0o644, opts.Force, result)
}

func ensureEnvExample(opts Options, result *Result) error {
	path := filepath.Join(opts.Root, ".env.app.example")
	content := `# Example app env file for local emulation
RESISTACK_PROJECT=` + opts.ProjectName + `
APP_PORT=8080
`
	return writeOrSkip(path, []byte(content), 0o644, opts.Force, result)
}

func writeOrSkip(path string, content []byte, perm os.FileMode, force bool, result *Result) error {
	if _, err := os.Stat(path); err == nil && !force {
		result.Skipped = append(result.Skipped, path)
		return nil
	}
	if err := os.WriteFile(path, content, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	result.Written = append(result.Written, path)
	return nil
}
