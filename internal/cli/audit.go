package cli

import (
	"io"
	"os"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runAudit(args []string, out io.Writer, errOut io.Writer) error {
	fs := newFlagSet("audit")
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	dryRun := fs.Bool("dry-run", false, "Explain what audit will do while keeping the read-only execution path")
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
	_, err = stack.Audit(cfg, wd, *dryRun, out)
	return err
}
