package cli

import (
	"io"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runStatus(args []string, out io.Writer, errOut io.Writer) error {
	_, configPath, err := parseConfigFlag("status", args)
	if err != nil {
		return err
	}
	ctx, err := loadContext(*configPath, out, errOut)
	if err != nil {
		return err
	}
	return stack.Status(ctx.Config, ctx.Root, ctx.Out)
}
