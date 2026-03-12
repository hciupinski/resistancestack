package stack

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

func RotateDashboardPassword(cfg config.Config, configPath string, out io.Writer) error {
	if !cfg.Dashboard.BasicAuth.Enabled {
		return fmt.Errorf("dashboard.basic_auth.enabled must be true to rotate dashboard credentials")
	}

	password, err := generateSecret()
	if err != nil {
		return err
	}

	target := newTarget(cfg)
	command := fmt.Sprintf(
		"sudo htpasswd -bcB %s %s %s >/dev/null && sudo systemctl reload nginx",
		shellQuote("/etc/nginx/resistack-"+cfg.ProjectName+".htpasswd"),
		shellQuote(cfg.Dashboard.BasicAuth.Username),
		shellQuote(password),
	)
	if err := remote.Run(target, command, out, out); err != nil {
		return fmt.Errorf("rotate remote dashboard password: %w", err)
	}

	cfg.Dashboard.BasicAuth.Password = password
	if err := config.Save(configPath, cfg); err != nil {
		return err
	}

	fmt.Fprintf(out, "Dashboard password rotated for project %q.\n", cfg.ProjectName)
	fmt.Fprintf(out, "username: %s\n", cfg.Dashboard.BasicAuth.Username)
	fmt.Fprintf(out, "password: %s\n", password)
	fmt.Fprintf(out, "updated config: %s\n", configPath)
	return nil
}
