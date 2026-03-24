package cli

import (
	"io"
	"os"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runApply(args []string, out io.Writer, errOut io.Writer) error {
	fs := newFlagSet("apply")
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	dryRun := fs.Bool("dry-run", false, "Print intended changes without executing them")
	if err := fs.Parse(args); err != nil {
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
	return stack.Apply(cfg, wd, fs.Args(), *dryRun, out, errOut)
}
