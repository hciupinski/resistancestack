package cli

import (
	"flag"
	"io"
	"os"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/stack"
	"github.com/hciupinski/resistancestack/internal/validation"
)

func runDeploy(args []string, out io.Writer, errOut io.Writer) error {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	dryRun := fs.Bool("dry-run", false, "Print the remote provisioning script without executing")
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

	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	return stack.Deploy(cfg, wd, *dryRun, out, errOut)
}
