package doctor

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func FormatText(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Doctor generated at: %s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Mode: %s\n", report.Mode)
	fmt.Fprintf(&b, "Status: %s\n", report.Status)
	if len(report.Checks) == 0 {
		b.WriteString("No checks.\n")
		return b.String()
	}
	b.WriteString("\nChecks:\n")
	for _, check := range report.Checks {
		fmt.Fprintf(&b, "- [%s] %s (%s)\n", strings.ToUpper(check.Status), check.Description, check.Area)
		fmt.Fprintf(&b, "  detected: %s\n", check.DetectedValue)
		if check.Recommendation != "" {
			fmt.Fprintf(&b, "  recommendation: %s\n", check.Recommendation)
		}
	}
	return b.String()
}

func FormatJSON(report Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
