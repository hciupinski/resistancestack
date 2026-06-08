package observability

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

func Enable(cfg config.Config, root string, dryRun bool, out io.Writer, errOut io.Writer) error {
	target := remote.NewTarget(cfg)
	assets, err := BuildGrafanaAssetBundle(root, cfg)
	if err != nil {
		return err
	}
	script := BuildEnableScript(cfg)
	if dryRun {
		if assets.Configured {
			_, _ = fmt.Fprintf(out, "[resistack] custom Grafana assets: dashboards=%d alerting=%d files=%d\n", assets.DashboardCount, assets.AlertingCount, len(assets.Paths))
			for _, path := range assets.Paths {
				_, _ = fmt.Fprintf(out, "[resistack] would deploy Grafana asset %s\n", path)
			}
		}
		_, _ = fmt.Fprintln(out, script)
		return nil
	}
	_, _ = fmt.Fprintf(out, "[resistack] enabling observability on %s:%d\n", target.Host, target.Port)
	if assets.Configured {
		_, _ = fmt.Fprintf(out, "[resistack] uploading custom Grafana assets: dashboards=%d alerting=%d files=%d\n", assets.DashboardCount, assets.AlertingCount, len(assets.Paths))
		if err := remote.Upload(target, grafanaAssetsRemoteArchive, assets.Archive); err != nil {
			return err
		}
	}
	return remote.RunScript(target, script, out, errOut)
}

func Disable(cfg config.Config, out io.Writer, errOut io.Writer) error {
	target := remote.NewTarget(cfg)
	return remote.RunScript(target, BuildDisableScript(cfg), out, errOut)
}
