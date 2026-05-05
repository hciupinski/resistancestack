package audit

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

func FormatText(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Audit generated at: %s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Top severity: %s\n", report.Summary.TopSeverity)
	fmt.Fprintf(&b, "Security score: %d/100\n", report.Summary.SecurityScore)
	for _, severity := range []string{config.SeverityCritical, config.SeverityHigh, config.SeverityMedium, config.SeverityLow, config.SeverityNotChecked} {
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

func FormatHTML(report Report) string {
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>ResistanceStack Audit Report</title>\n")
	b.WriteString("<style>")
	b.WriteString("body{margin:0;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;background:#f6f7f9;color:#17202a;line-height:1.5}")
	b.WriteString("main{max-width:1120px;margin:0 auto;padding:32px 20px 48px}")
	b.WriteString("section{margin-top:24px}")
	b.WriteString("h1{font-size:30px;margin:0 0 6px}h2{font-size:20px;margin:0 0 12px}h3{font-size:16px;margin:0 0 8px}")
	b.WriteString(".meta{color:#5f6b7a;margin:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}")
	b.WriteString(".panel,.finding{background:#fff;border:1px solid #dfe3e8;border-radius:8px;padding:16px}")
	b.WriteString(".metric{font-size:28px;font-weight:700}.label{color:#5f6b7a;font-size:13px;text-transform:uppercase;letter-spacing:.04em}")
	b.WriteString(".score{font-size:42px}.severity{display:inline-block;border-radius:999px;padding:2px 9px;font-size:12px;font-weight:700;text-transform:uppercase}")
	b.WriteString(".critical{background:#ffe4e4;color:#9f1239}.high{background:#ffedd5;color:#9a3412}.medium{background:#fef3c7;color:#854d0e}.low{background:#e0f2fe;color:#075985}.not_checked{background:#e5e7eb;color:#374151}")
	b.WriteString("table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #dfe3e8;border-radius:8px;overflow:hidden}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #edf0f2;vertical-align:top}th{background:#f0f3f6;color:#344054}tr:last-child td{border-bottom:0}")
	b.WriteString("dl{margin:10px 0 0}dt{font-weight:700;margin-top:8px}dd{margin:2px 0 0;color:#344054}ol,ul{margin:8px 0 0 20px;padding:0}.empty{color:#5f6b7a;background:#fff;border:1px solid #dfe3e8;border-radius:8px;padding:16px}")
	b.WriteString("</style>\n</head>\n<body>\n<main>\n")
	b.WriteString("<header><h1>ResistanceStack Audit Report</h1>")
	fmt.Fprintf(&b, "<p class=\"meta\">Generated at %s</p></header>\n", esc(report.GeneratedAt.Format(time.RFC3339)))

	b.WriteString("<section aria-labelledby=\"summary\"><h2 id=\"summary\">Summary</h2><div class=\"grid\">")
	fmt.Fprintf(&b, "<div class=\"panel\"><div class=\"label\">Security score</div><div class=\"metric score\">%d/100</div></div>", report.Summary.SecurityScore)
	fmt.Fprintf(&b, "<div class=\"panel\"><div class=\"label\">Top severity</div><div class=\"metric\">%s</div></div>", esc(report.Summary.TopSeverity))
	fmt.Fprintf(&b, "<div class=\"panel\"><div class=\"label\">Findings</div><div class=\"metric\">%d</div></div>", len(report.Findings))
	fmt.Fprintf(&b, "<div class=\"panel\"><div class=\"label\">Auto-remediable</div><div class=\"metric\">%d</div></div>", countAutoRemediable(report.Findings))
	b.WriteString("</div></section>\n")

	b.WriteString("<section aria-labelledby=\"severity\"><h2 id=\"severity\">Severity</h2><div class=\"grid\">")
	for _, severity := range severityList() {
		fmt.Fprintf(&b, "<div class=\"panel\"><span class=\"severity %s\">%s</span><div class=\"metric\">%d</div></div>", esc(severity), esc(severity), report.Summary.BySeverity[severity])
	}
	b.WriteString("</div></section>\n")

	b.WriteString("<section aria-labelledby=\"areas\"><h2 id=\"areas\">Checked Areas</h2><table><thead><tr><th>Area</th><th>Status</th><th>Reason</th></tr></thead><tbody>")
	writeAreaRow(&b, "repo", report.Snapshot.Areas.Repo)
	writeAreaRow(&b, "host", report.Snapshot.Areas.Host)
	writeAreaRow(&b, "cloud/external", report.Snapshot.Areas.CloudExternal)
	b.WriteString("</tbody></table></section>\n")

	b.WriteString("<section aria-labelledby=\"findings\"><h2 id=\"findings\">Findings</h2>")
	nonNotChecked := filterFindings(report.Findings, false)
	if len(nonNotChecked) == 0 {
		b.WriteString("<p class=\"empty\">No checked-area findings.</p>")
	} else {
		for _, finding := range nonNotChecked {
			writeFinding(&b, finding)
		}
	}
	b.WriteString("</section>\n")

	b.WriteString("<section aria-labelledby=\"remediation\"><h2 id=\"remediation\">Remediation Plan</h2>")
	if len(report.Remediation) == 0 {
		b.WriteString("<p class=\"empty\">No auto-remediable findings in this report.</p>")
	} else {
		for _, item := range report.Remediation {
			fmt.Fprintf(&b, "<div class=\"panel\"><h3>%s</h3><p>%s</p><ol>", esc(item.Module), esc(item.Reason))
			for _, step := range item.Steps {
				fmt.Fprintf(&b, "<li>%s</li>", esc(step))
			}
			b.WriteString("</ol></div>")
		}
	}
	b.WriteString("</section>\n")

	b.WriteString("<section aria-labelledby=\"not-checked\"><h2 id=\"not-checked\">Not Checked</h2>")
	notChecked := filterFindings(report.Findings, true)
	if len(notChecked) == 0 {
		b.WriteString("<p class=\"empty\">All configured audit areas were checked.</p>")
	} else {
		for _, finding := range notChecked {
			writeFinding(&b, finding)
		}
	}
	b.WriteString("</section>\n")

	b.WriteString("</main>\n</body>\n</html>\n")
	return b.String()
}

func severityList() []string {
	return []string{config.SeverityCritical, config.SeverityHigh, config.SeverityMedium, config.SeverityLow, config.SeverityNotChecked}
}

func writeAreaRow(b *strings.Builder, name string, area inventory.AreaStatus) {
	status := strings.TrimSpace(area.Status)
	if status == "" {
		status = "unknown"
	}
	fmt.Fprintf(b, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", esc(name), esc(status), esc(area.Reason))
}

func writeFinding(b *strings.Builder, finding Finding) {
	fmt.Fprintf(b, "<article class=\"finding\"><h3><span class=\"severity %s\">%s</span> %s</h3>", esc(finding.Severity), esc(finding.Severity), esc(finding.Description))
	fmt.Fprintf(b, "<p class=\"meta\">%s | %s | auto-remediable: %t</p>", esc(finding.ID), esc(finding.Module), finding.AutoRemediable)
	b.WriteString("<dl>")
	fmt.Fprintf(b, "<dt>Detected value</dt><dd>%s</dd>", esc(finding.DetectedValue))
	fmt.Fprintf(b, "<dt>Risk</dt><dd>%s</dd>", esc(finding.Risk))
	fmt.Fprintf(b, "<dt>Recommendation</dt><dd>%s</dd>", esc(finding.Recommendation))
	b.WriteString("</dl></article>")
}

func filterFindings(findings []Finding, notChecked bool) []Finding {
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if (finding.Severity == config.SeverityNotChecked) == notChecked {
			result = append(result, finding)
		}
	}
	return result
}

func countAutoRemediable(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.AutoRemediable {
			count++
		}
	}
	return count
}

func esc(value string) string {
	return html.EscapeString(value)
}
