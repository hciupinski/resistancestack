package cli

import (
	"io"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runStatus(args []string, out io.Writer, errOut io.Writer) error {
	fs, configPath, envName := newConfigFlagSet("status")
	selection, err := parseConfigSelection(fs, args, configPath, envName)
	if err != nil {
		return err
	}
	ctx, err := loadContext(selection, out, errOut)
	if err != nil {
		return err
	}
	return stack.Status(ctx.Config, ctx.Root, ctx.Out)
}
