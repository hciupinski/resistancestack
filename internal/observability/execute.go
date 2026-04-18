package observability

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

func Enable(cfg config.Config, dryRun bool, out io.Writer, errOut io.Writer) error {
	target := remote.NewTarget(cfg)
	script := BuildEnableScript(cfg)
	if dryRun {
		_, _ = fmt.Fprintln(out, script)
		return nil
	}
	_, _ = fmt.Fprintf(out, "[resistack] enabling observability on %s:%d\n", target.Host, target.Port)
	return remote.RunScript(target, script, out, errOut)
}

func Disable(cfg config.Config, out io.Writer, errOut io.Writer) error {
	target := remote.NewTarget(cfg)
	return remote.RunScript(target, BuildDisableScript(cfg), out, errOut)
}
