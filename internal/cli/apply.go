package cli

import (
	"io"
	"strings"

	"github.com/hciupinski/resistancestack/internal/stack"
)

func runApply(args []string, out io.Writer, errOut io.Writer) error {
	args = normalizeApplyArgs(args)
	fs, configPath, envName := newConfigFlagSet("apply")
	dryRun := fs.Bool("dry-run", false, "Print intended changes without executing them")
	selection, err := parseConfigSelection(fs, args, configPath, envName)
	if err != nil {
		return err
	}
	ctx, err := loadContext(selection, out, errOut)
	if err != nil {
		return err
	}
	return stack.Apply(ctx.Config, ctx.Root, fs.Args(), *dryRun, ctx.Out, ctx.ErrOut)
}

func normalizeApplyArgs(args []string) []string {
	flags := make([]string, 0, len(args))
	modules := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--dry-run":
			flags = append(flags, arg)
		case arg == "--config" || arg == "--env":
			flags = append(flags, arg)
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		case strings.HasPrefix(arg, "--config="), strings.HasPrefix(arg, "--env="):
			flags = append(flags, arg)
		default:
			modules = append(modules, arg)
		}
	}

	return append(flags, modules...)
}
