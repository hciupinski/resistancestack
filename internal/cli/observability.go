package cli

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/observability"
)

func runObservability(args []string, out io.Writer, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("observability requires a subcommand: enable or disable")
	}
	fs := newFlagSet("observability " + args[0])
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	dryRun := fs.Bool("dry-run", false, "Print the observability changes without executing them")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfigWithValidation(*configPath, errOut)
	if err != nil {
		return err
	}

	switch args[0] {
	case "enable":
		return observability.Enable(cfg, *dryRun, out, errOut)
	case "disable":
		return observability.Disable(cfg, out, errOut)
	default:
		return fmt.Errorf("unknown observability subcommand %q", args[0])
	}
}
