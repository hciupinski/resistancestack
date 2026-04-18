package cli

import (
	"io"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runInventory(args []string, out io.Writer, errOut io.Writer) error {
	fs, configPath, envName := newConfigFlagSet("inventory")
	selection, err := parseConfigSelection(fs, args, configPath, envName)
	if err != nil {
		return err
	}
	ctx, err := loadContext(selection, out, errOut)
	if err != nil {
		return err
	}
	_, err = stack.Inventory(ctx.Config, ctx.Root, ctx.Out)
	return err
}
