package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
)

type ConfigSelection struct {
	ConfigPath string
	Env        string
}

type Context struct {
	ConfigPath  string
	OverlayPath string
	Env         string
	Root        string
	Config      config.Config
	Out         io.Writer
	ErrOut      io.Writer
}

func newConfigFlagSet(name string) (*flag.FlagSet, *string, *string) {
	fs := newFlagSet(name)
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	envName := fs.String("env", "", "Environment overlay name")
	return fs, configPath, envName
}

func parseConfigSelection(fs *flag.FlagSet, args []string, configPath *string, envName *string) (ConfigSelection, error) {
	if err := fs.Parse(args); err != nil {
		return ConfigSelection{}, err
	}
	selection := ConfigSelection{
		ConfigPath: strings.TrimSpace(*configPath),
		Env:        strings.TrimSpace(*envName),
	}
	if err := config.ValidateEnvName(selection.Env); err != nil {
		return ConfigSelection{}, err
	}
	return selection, nil
}

func loadContext(selection ConfigSelection, out io.Writer, errOut io.Writer) (Context, error) {
	cfg, overlayPath, err := loadConfigWithValidation(selection.ConfigPath, selection.Env, errOut)
	if err != nil {
		return Context{}, err
	}

	root, err := os.Getwd()
	if err != nil {
		return Context{}, err
	}

	if selection.Env != "" {
		fmt.Fprintf(errOut, "using environment %q (base: %s, overlay: %s)\n", selection.Env, selection.ConfigPath, overlayPath)
	}

	return Context{
		ConfigPath:  selection.ConfigPath,
		OverlayPath: overlayPath,
		Env:         selection.Env,
		Root:        root,
		Config:      cfg,
		Out:         out,
		ErrOut:      errOut,
	}, nil
}
