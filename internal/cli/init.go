package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
)

func runInit(args []string, out io.Writer) error {
	fs := newFlagSet("init")
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	force := fs.Bool("force", false, "Overwrite existing configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	projectName := fs.Arg(0)
	if projectName == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
		projectName = filepath.Base(wd)
	}

	result, err := config.EnsureDefaultConfig(*configPath, projectName, *force)
	if err != nil {
		return err
	}

	switch {
	case result.Created && *force:
		fmt.Fprintf(out, "Overwrote %s with the latest security baseline defaults for project %q\n", *configPath, projectName)
	case result.Created:
		fmt.Fprintf(out, "Created %s for security baseline project %q\n", *configPath, projectName)
	case len(result.Added) > 0:
		fmt.Fprintf(
			out,
			"Updated %s with %d new configuration defaults for project %q: %s\n",
			*configPath,
			len(result.Added),
			projectName,
			strings.Join(result.Added, ", "),
		)
	default:
		fmt.Fprintf(out, "%s is already up to date for project %q\n", *configPath, projectName)
	}
	return nil
}
