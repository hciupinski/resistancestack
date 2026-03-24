package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

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

	if _, err := os.Stat(*configPath); err == nil && !*force {
		return fmt.Errorf("%s already exists; use --force to overwrite", *configPath)
	}

	cfg := config.Default(projectName)
	if err := config.Save(*configPath, cfg); err != nil {
		return err
	}

	fmt.Fprintf(out, "Created %s for security baseline project %q\n", *configPath, projectName)
	return nil
}
