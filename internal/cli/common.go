package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

const defaultConfigPath = "resistack.yaml"

func loadValidatedConfig(args []string, errOut io.Writer, commandName string) (string, error) {
	fs := flag.NewFlagSet(commandName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", defaultConfigPath, "Path to configuration file")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *configPath, nil
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
