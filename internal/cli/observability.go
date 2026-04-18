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
	fs, configPath, envName := newConfigFlagSet("observability " + args[0])
	dryRun := fs.Bool("dry-run", false, "Print the observability changes without executing them")
	selection, err := parseConfigSelection(fs, args[1:], configPath, envName)
	if err != nil {
		return err
	}
	ctx, err := loadContext(selection, out, errOut)
	if err != nil {
		return err
	}

	switch args[0] {
	case "enable":
		return observability.Enable(ctx.Config, *dryRun, ctx.Out, ctx.ErrOut)
	case "disable":
		return observability.Disable(ctx.Config, ctx.Out, ctx.ErrOut)
	default:
		return fmt.Errorf("unknown observability subcommand %q", args[0])
	}
}
