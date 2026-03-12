package cli

import (
	"fmt"
	"io"
)

func Run(args []string, out io.Writer, errOut io.Writer) error {
	if len(args) == 0 {
		printUsage(out)
		return nil
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage(out)
		return nil
	case "init":
		return runInit(args[1:], out)
	case "validate":
		return runValidate(args[1:], out, errOut)
	case "deploy":
		return runDeploy(args[1:], out, errOut)
	case "scaffold":
		return runScaffold(args[1:], out)
	case "status":
		return runStatus(args[1:], out, errOut)
	case "rotate-secrets":
		return runRotateSecrets(args[1:], out, errOut)
	case "uninstall":
		return runUninstall(args[1:], out, errOut)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, "resistack - ResistanceStack CLI")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  resistack <command> [flags]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Commands:")
	fmt.Fprintln(out, "  init [project-name]       Generate resistack.yaml")
	fmt.Fprintln(out, "  validate                  Validate resistack.yaml")
	fmt.Fprintln(out, "  deploy [--dry-run]        Provision and deploy stack over SSH")
	fmt.Fprintln(out, "  scaffold [project-name]   Generate local starter files")
	fmt.Fprintln(out, "  status                    Show remote service status and security signals")
	fmt.Fprintln(out, "  rotate-secrets            Rotate dashboard credentials")
	fmt.Fprintln(out, "  uninstall --retain-data   Remove stack from host")
}
