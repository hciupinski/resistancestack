package cli

import (
	"flag"
	"io"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/stack"
)

func runUninstall(args []string, out io.Writer, errOut io.Writer) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	retainData := fs.Bool("retain-data", true, "Keep stateful data volumes on uninstall")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	return stack.Uninstall(cfg, *retainData, out, errOut)
}
