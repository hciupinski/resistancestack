package cli

import (
	"io"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runInventory(args []string, out io.Writer, errOut io.Writer) error {
	_, configPath, err := parseConfigFlag("inventory", args)
	if err != nil {
		return err
	}
	ctx, err := loadContext(*configPath, out, errOut)
	if err != nil {
		return err
	}
	_, err = stack.Inventory(ctx.Config, ctx.Root, ctx.Out)
	return err
}
