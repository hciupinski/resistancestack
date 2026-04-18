package cli

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runRollback(args []string, out io.Writer, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("rollback requires a subcommand: host")
	}
	fs, configPath, envName := newConfigFlagSet("rollback " + args[0])
	selection, err := parseConfigSelection(fs, args[1:], configPath, envName)
	if err != nil {
		return err
	}
	ctx, err := loadContext(selection, out, errOut)
	if err != nil {
		return err
	}

	switch args[0] {
	case "host":
		return stack.RollbackHost(ctx.Config, out, errOut)
	default:
		return fmt.Errorf("unknown rollback subcommand %q", args[0])
	}
}
