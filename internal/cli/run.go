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
	case "inventory":
		return runInventory(args[1:], out, errOut)
	case "audit":
		return runAudit(args[1:], out, errOut)
	case "apply":
		return runApply(args[1:], out, errOut)
	case "status":
		return runStatus(args[1:], out, errOut)
	case "ci":
		return runCI(args[1:], out, errOut)
	case "observability":
		return runObservability(args[1:], out, errOut)
	case "rollback":
		return runRollback(args[1:], out, errOut)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, "resistack - ResistanceStack v2 CLI")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  resistack <command> [flags]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Commands:")
	fmt.Fprintln(out, "  init [project-name]                 Generate resistack.yaml")
	fmt.Fprintln(out, "  inventory                           Detect current VPS and repo state")
	fmt.Fprintln(out, "  audit [--dry-run]                   Generate risk report and remediation plan")
	fmt.Fprintln(out, "  apply [modules...] [--dry-run]      Apply selected security modules")
	fmt.Fprintln(out, "  status                              Show host, observability, and security posture")
	fmt.Fprintln(out, "  ci generate                         Generate standalone security workflows")
	fmt.Fprintln(out, "  ci validate                         Validate generated security workflows")
	fmt.Fprintln(out, "  observability enable [--dry-run]    Enable local observability baseline")
	fmt.Fprintln(out, "  observability disable               Disable local observability baseline")
	fmt.Fprintln(out, "  rollback host                       Roll back the last host-hardening change")
}
