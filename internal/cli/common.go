package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/validation"
)

const defaultConfigPath = "resistack.yaml"

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func loadConfigWithValidation(configPath string, errOut io.Writer) (config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return config.Config{}, err
	}
	warnings, errs := validation.Check(cfg)
	for _, warning := range warnings {
		fmt.Fprintf(errOut, "warning: %s\n", warning)
	}
	writeValidationErrors(errOut, errs)
	if len(errs) > 0 {
		return config.Config{}, invalidConfigError(errs)
	}
	return cfg, nil
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
