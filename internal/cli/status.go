package cli

import (
	"flag"
	"io"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/stack"
	"github.com/hciupinski/resistancestack/internal/validation"
)

func runStatus(args []string, out io.Writer, errOut io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	_, errs := validation.Check(cfg)
	writeValidationErrors(errOut, errs)
	if len(errs) > 0 {
		return invalidConfigError(errs)
	}

	return stack.Status(cfg, out)
}
