package cli

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runCI(args []string, out io.Writer, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("ci requires a subcommand: generate or validate")
	}
	_, configPath, err := parseConfigFlag("ci "+args[0], args[1:])
	if err != nil {
		return err
	}
	ctx, err := loadContext(*configPath, out, errOut)
	if err != nil {
		return err
	}

	switch args[0] {
	case "generate":
		return stack.GenerateCI(ctx.Config, ctx.Root, ctx.Out)
	case "validate":
		return stack.ValidateCI(ctx.Config, ctx.Root, ctx.Out)
	default:
		return fmt.Errorf("unknown ci subcommand %q", args[0])
	}
}
