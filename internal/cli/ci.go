package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runCI(args []string, out io.Writer, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("ci requires a subcommand: generate or validate")
	}
	fs := newFlagSet("ci " + args[0])
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfigWithValidation(*configPath, errOut)
	if err != nil {
		return err
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	switch args[0] {
	case "generate":
		return stack.GenerateCI(cfg, wd, out)
	case "validate":
		return stack.ValidateCI(cfg, wd, out)
	default:
		return fmt.Errorf("unknown ci subcommand %q", args[0])
	}
}
