package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hciupinski/resistancestack/internal/scaffold"
)

func runScaffold(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scaffold", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "resistack.local.yaml", "Path for generated local config")
	force := fs.Bool("force", false, "Overwrite files if they already exist")
	withCI := fs.Bool("with-ci", true, "Generate .github/workflows/security.yml")
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

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}

	result, err := scaffold.Generate(scaffold.Options{
		Root:        wd,
		ProjectName: projectName,
		ConfigPath:  *configPath,
		Force:       *force,
		WithCI:      *withCI,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Scaffold completed for project %q.\n", projectName)
	for _, path := range result.Written {
		fmt.Fprintf(out, "written: %s\n", path)
	}
	for _, path := range result.Skipped {
		fmt.Fprintf(out, "skipped: %s\n", path)
	}
	return nil
}
