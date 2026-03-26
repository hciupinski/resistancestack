package hosthardening

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

func Apply(cfg config.Config, dryRun bool, out io.Writer, errOut io.Writer) error {
	target := remote.NewTarget(cfg)

	if dryRun {
		plan, previewErr := PreviewAccessPlan(target, cfg)
		if previewErr != nil {
			fmt.Fprintf(errOut, "warning: unable to derive current SSH session for dry-run: %v\n", previewErr)
			plan = BuildAccessPlan(cfg, "")
		}
		fmt.Fprintln(out, FormatAccessPlan(plan))
		fmt.Fprintln(out, "Generated host-hardening script:")
		fmt.Fprintln(out, BuildApplyScript(cfg))
		if plan.BlockingReason != "" {
			return fmt.Errorf("host hardening preview failed: %s", plan.BlockingReason)
		}
		return nil
	}

	return remote.RunScript(target, BuildApplyScript(cfg), out, errOut)
}

func Rollback(cfg config.Config, out io.Writer, errOut io.Writer) error {
	target := remote.NewTarget(cfg)
	return remote.RunScript(target, BuildRollbackScript(cfg), out, errOut)
}
