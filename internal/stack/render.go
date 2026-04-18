package stack

import (
	"fmt"
	"io"
	"strings"

	"github.com/hciupinski/resistancestack/internal/audit"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

func renderInventory(out io.Writer, snapshot inventory.Snapshot) {
	fmt.Fprintf(out, "Host: %s\n", snapshot.Host.Hostname)
	fmt.Fprintf(out, "OS: %s\n", snapshot.Host.OS)
	fmt.Fprintf(out, "Proxy: %s\n", snapshot.Proxy.Kind)
	fmt.Fprintf(out, "Runtime: %s\n", snapshot.Runtime.Kind)
	fmt.Fprintf(out, "UFW: %s\n", snapshot.UFW.Status)
	fmt.Fprintf(out, "Fail2ban: %s\n", snapshot.Fail2ban.Status)
	fmt.Fprintf(out, "Passwordless sudo: %t\n", snapshot.PasswordlessSudo)
	if len(snapshot.Repo.Technologies) > 0 {
		fmt.Fprintf(out, "Repo technologies: %s\n", stringsJoin(snapshot.Repo.Technologies))
	}
	if len(snapshot.Repo.GitHubWorkflows) > 0 {
		fmt.Fprintf(out, "GitHub workflows: %s\n", stringsJoin(snapshot.Repo.GitHubWorkflows))
	}
}

func formatStatus(snapshot inventory.Snapshot, report audit.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host: %s (%s)\n", snapshot.Host.Hostname, snapshot.Host.OS)
	fmt.Fprintf(&b, "Proxy: %s\n", snapshot.Proxy.Kind)
	fmt.Fprintf(&b, "Runtime: %s\n", snapshot.Runtime.Kind)
	fmt.Fprintf(&b, "UFW: %s\n", snapshot.UFW.Status)
	fmt.Fprintf(&b, "Fail2ban: %s\n", snapshot.Fail2ban.Status)
	fmt.Fprintf(&b, "Observability: %s\n", snapshot.Observability.Status)
	if snapshot.Observability.DashboardURL != "" {
		fmt.Fprintf(&b, "Dashboard: %s\n", snapshot.Observability.DashboardURL)
	}
	if snapshot.Observability.CredentialsPath != "" {
		fmt.Fprintf(&b, "Dashboard credentials: %s\n", snapshot.Observability.CredentialsPath)
	}
	if snapshot.Observability.LastSnapshotAt != "" {
		fmt.Fprintf(&b, "Last snapshot: %s\n", snapshot.Observability.LastSnapshotAt)
	}
	if snapshot.Observability.Enabled {
		fmt.Fprintf(
			&b,
			"Observability services: snapshot=%s timer=%s grafana=%s loki=%s alloy=%s\n",
			snapshot.Observability.SnapshotService.Status,
			snapshot.Observability.SnapshotTimer.Status,
			snapshot.Observability.GrafanaService.Status,
			snapshot.Observability.LokiService.Status,
			snapshot.Observability.AlloyService.Status,
		)
	}
	fmt.Fprintf(&b, "Security posture: %s\n", report.Summary.TopSeverity)
	fmt.Fprintf(&b, "Findings: critical=%d high=%d medium=%d low=%d\n",
		report.Summary.BySeverity[config.SeverityCritical],
		report.Summary.BySeverity[config.SeverityHigh],
		report.Summary.BySeverity[config.SeverityMedium],
		report.Summary.BySeverity[config.SeverityLow],
	)

	if len(snapshot.Containers) > 0 {
		b.WriteString("Containers:\n")
		for _, container := range snapshot.Containers {
			fmt.Fprintf(&b, "- %s (%s, restarts=%d)\n", container.Name, container.Status, container.Restarts)
		}
	}
	if len(report.Findings) > 0 {
		b.WriteString("Top findings:\n")
		limit := min(5, len(report.Findings))
		for _, finding := range report.Findings[:limit] {
			fmt.Fprintf(&b, "- [%s] %s\n", finding.Severity, finding.Description)
		}
	}

	return b.String()
}

func stringsJoin(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}
