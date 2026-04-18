package cli

import (
	"io"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runApply(args []string, out io.Writer, errOut io.Writer) error {
	fs, configPath, envName := newConfigFlagSet("apply")
	dryRun := fs.Bool("dry-run", false, "Print intended changes without executing them")
	selection, err := parseConfigSelection(fs, args, configPath, envName)
	if err != nil {
		return err
	}
	ctx, err := loadContext(selection, out, errOut)
	if err != nil {
		return err
	}
	return stack.Apply(ctx.Config, ctx.Root, fs.Args(), *dryRun, ctx.Out, ctx.ErrOut)
}
