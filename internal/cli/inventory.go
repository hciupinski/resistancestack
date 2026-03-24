package cli

import (
	"io"
	"os"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runInventory(args []string, out io.Writer, errOut io.Writer) error {
	fs := newFlagSet("inventory")
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
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
	_, err = stack.Inventory(cfg, wd, out)
	return err
}
