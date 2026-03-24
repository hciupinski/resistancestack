package stack

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/audit"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

func Status(cfg config.Config, root string, out io.Writer) error {
	snapshot, err := inventory.Collect(cfg, root)
	if err != nil {
		return err
	}
	report := audit.Evaluate(cfg, snapshot)

	fmt.Fprintf(out, "Host: %s (%s)\n", snapshot.Host.Hostname, snapshot.Host.OS)
	fmt.Fprintf(out, "Proxy: %s\n", snapshot.Proxy.Kind)
	fmt.Fprintf(out, "Runtime: %s\n", snapshot.Runtime.Kind)
	fmt.Fprintf(out, "UFW: %s\n", snapshot.UFW.Status)
	fmt.Fprintf(out, "Fail2ban: %s\n", snapshot.Fail2ban.Status)
	fmt.Fprintf(out, "Observability: %s\n", snapshot.Observability.Status)
	fmt.Fprintf(out, "Security posture: %s\n", report.Summary.TopSeverity)
	fmt.Fprintf(out, "Findings: critical=%d high=%d medium=%d low=%d\n",
		report.Summary.BySeverity[config.SeverityCritical],
		report.Summary.BySeverity[config.SeverityHigh],
		report.Summary.BySeverity[config.SeverityMedium],
		report.Summary.BySeverity[config.SeverityLow],
	)

	if len(snapshot.Containers) > 0 {
		fmt.Fprintln(out, "Containers:")
		for _, container := range snapshot.Containers {
			fmt.Fprintf(out, "- %s (%s, restarts=%d)\n", container.Name, container.Status, container.Restarts)
		}
	}
	if len(report.Findings) > 0 {
		fmt.Fprintln(out, "Top findings:")
		limit := min(5, len(report.Findings))
		for _, finding := range report.Findings[:limit] {
			fmt.Fprintf(out, "- [%s] %s\n", finding.Severity, finding.Description)
		}
	}
	return nil
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
