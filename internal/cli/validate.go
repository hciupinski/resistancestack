package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/validation"
)

func runValidate(args []string, out io.Writer, errOut io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	warnings, errs := validation.Check(cfg)
	for _, warning := range warnings {
		fmt.Fprintf(out, "warning: %s\n", warning)
	}
	writeValidationErrors(errOut, errs)
	if len(errs) > 0 {
		return invalidConfigError(errs)
	}

	fmt.Fprintln(out, "Configuration is valid.")
	return nil
}
