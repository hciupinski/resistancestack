package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/validation"
)

const defaultConfigPath = "resistack.yaml"

type loadConfigOptions struct {
	Local        bool
	DefaultRoot  string
	OutputFormat string
}

func loadConfigWithValidationOptions(configPath string, env string, errOut io.Writer, opts loadConfigOptions) (config.Config, string, error) {
	cfg, overlayPath, err := config.LoadWithEnv(configPath, env)
	if err != nil {
		if !opts.Local || env != "" || !os.IsNotExist(rootCause(err)) {
			return config.Config{}, "", err
		}
		projectName := "resistack"
		if opts.DefaultRoot != "" {
			projectName = filepath.Base(opts.DefaultRoot)
		}
		cfg = config.Default(projectName)
	}
	if strings.TrimSpace(opts.OutputFormat) != "" {
		cfg.Reporting.Format = strings.ToLower(strings.TrimSpace(opts.OutputFormat))
	}
	warnings, errs := validation.CheckWithOptions(cfg, validation.Options{Local: opts.Local})
	for _, warning := range warnings {
		fmt.Fprintf(errOut, "warning: %s\n", warning)
	}
	writeValidationErrors(errOut, errs)
	if len(errs) > 0 {
		return config.Config{}, "", invalidConfigError(errs)
	}
	return cfg, overlayPath, nil
}

func rootCause(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}

func writeValidationErrors(errOut io.Writer, errs []error) {
	for _, validationErr := range errs {
		fmt.Fprintf(errOut, "validation error: %v\n", validationErr)
	}
}

func invalidConfigError(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return errors.New("configuration is invalid")
}
