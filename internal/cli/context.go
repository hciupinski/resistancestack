package cli

import (
	"flag"
	"io"
	"os"

	"github.com/hciupinski/resistancestack/internal/config"
)

type Context struct {
	ConfigPath string
	Root       string
	Config     config.Config
	Out        io.Writer
	ErrOut     io.Writer
}

func parseConfigFlag(name string, args []string) (*flag.FlagSet, *string, error) {
	fs := newFlagSet(name)
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	return fs, configPath, nil
}

func loadContext(configPath string, out io.Writer, errOut io.Writer) (Context, error) {
	cfg, err := loadConfigWithValidation(configPath, errOut)
	if err != nil {
		return Context{}, err
	}

	root, err := os.Getwd()
	if err != nil {
		return Context{}, err
	}

	return Context{
		ConfigPath: configPath,
		Root:       root,
		Config:     cfg,
		Out:        out,
		ErrOut:     errOut,
	}, nil
}
