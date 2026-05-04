package main

import (
	"fmt"
	"os"

	"github.com/hciupinski/resistancestack/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(cli.ExitCode(err))
	}
}
