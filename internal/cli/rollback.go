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
	fs := newFlagSet("rollback " + args[0])
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfigWithValidation(*configPath, errOut)
	if err != nil {
		return err
	}

	switch args[0] {
	case "host":
		return stack.RollbackHost(cfg, out, errOut)
	default:
		return fmt.Errorf("unknown rollback subcommand %q", args[0])
	}
}
