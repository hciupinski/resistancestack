package cli

import (
	"io"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runAudit(args []string, out io.Writer, errOut io.Writer) error {
	fs, configPath, envName := newConfigFlagSet("audit")
	dryRun := fs.Bool("dry-run", false, "Explain what audit will do while keeping the read-only execution path")
	selection, err := parseConfigSelection(fs, args, configPath, envName)
	if err != nil {
		return err
	}
	ctx, err := loadContext(selection, out, errOut)
	if err != nil {
		return err
	}
	_, err = stack.Audit(ctx.Config, ctx.Root, *dryRun, ctx.Out)
	return err
}
