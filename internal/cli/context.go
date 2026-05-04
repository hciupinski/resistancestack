package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/hciupinski/resistancestack/internal/config"
)

type ConfigSelection struct {
	ConfigPath   string
	Env          string
	OutputFormat string
	Local        bool
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

func loadContext(selection ConfigSelection, out io.Writer, errOut io.Writer) (Context, error) {
	root, err := os.Getwd()
	if err != nil {
		return Context{}, err
	}

	cfg, overlayPath, err := loadConfigWithValidationOptions(selection.ConfigPath, selection.Env, errOut, loadConfigOptions{
		Local:        selection.Local,
		DefaultRoot:  root,
		OutputFormat: selection.OutputFormat,
	})
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
