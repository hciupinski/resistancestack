package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
)

func FormatText(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Audit generated at: %s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Top severity: %s\n", report.Summary.TopSeverity)
	for _, severity := range []string{config.SeverityCritical, config.SeverityHigh, config.SeverityMedium, config.SeverityLow} {
		fmt.Fprintf(&b, "%s: %d\n", severity, report.Summary.BySeverity[severity])
	}
	if len(report.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	b.WriteString("\nFindings:\n")
	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "- [%s] %s (%s)\n", strings.ToUpper(finding.Severity), finding.Description, finding.Module)
		fmt.Fprintf(&b, "  detected: %s\n", finding.DetectedValue)
		fmt.Fprintf(&b, "  risk: %s\n", finding.Risk)
		fmt.Fprintf(&b, "  recommendation: %s\n", finding.Recommendation)
		fmt.Fprintf(&b, "  auto-remediable: %t\n", finding.AutoRemediable)
	}
	if len(report.Remediation) > 0 {
		b.WriteString("\nRemediation plan:\n")
		for _, item := range report.Remediation {
			fmt.Fprintf(&b, "- %s: %s\n", item.Module, item.Reason)
			for _, step := range item.Steps {
				fmt.Fprintf(&b, "  - %s\n", step)
			}
		}
	}
	return b.String()
}
