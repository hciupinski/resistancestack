package audit

import (
	"testing"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

func TestFormatText_RendersReport(t *testing.T) {
	report := Report{
		GeneratedAt: time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC),
		Snapshot:    inventory.Snapshot{},
		Summary: Summary{
			BySeverity: map[string]int{
				config.SeverityCritical: 1,
				config.SeverityHigh:     2,
				config.SeverityMedium:   0,
				config.SeverityLow:      0,
			},
			TopSeverity: config.SeverityCritical,
		},
		Findings: []Finding{{
			Severity:       config.SeverityCritical,
			Description:    "docker api exposed",
			Module:         "host-hardening",
			DetectedValue:  "tcp/2375 public",
			Risk:           "host compromise",
			Recommendation: "close port",
			AutoRemediable: false,
		}},
		Remediation: []Remediation{{
			Module: "host-hardening",
			Reason: "1 auto-remediable finding(s)",
			Steps:  []string{"close port"},
		}},
	}

	const want = "" +
		"Audit generated at: 2026-03-25T12:00:00Z\n" +
		"Top severity: critical\n" +
		"critical: 1\n" +
		"high: 2\n" +
		"medium: 0\n" +
		"low: 0\n" +
		"\n" +
		"Findings:\n" +
		"- [CRITICAL] docker api exposed (host-hardening)\n" +
		"  detected: tcp/2375 public\n" +
		"  risk: host compromise\n" +
		"  recommendation: close port\n" +
		"  auto-remediable: false\n" +
		"\n" +
		"Remediation plan:\n" +
		"- host-hardening: 1 auto-remediable finding(s)\n" +
		"  - close port\n"

	if got := FormatText(report); got != want {
		t.Fatalf("unexpected formatted report:\n%s", got)
	}
}

func TestFormatText_NoFindings(t *testing.T) {
	report := Report{
		GeneratedAt: time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC),
		Summary: Summary{
			BySeverity: map[string]int{
				config.SeverityCritical: 0,
				config.SeverityHigh:     0,
				config.SeverityMedium:   0,
				config.SeverityLow:      0,
			},
			TopSeverity: config.SeverityLow,
		},
	}

	const want = "" +
		"Audit generated at: 2026-03-25T12:00:00Z\n" +
		"Top severity: low\n" +
		"critical: 0\n" +
		"high: 0\n" +
		"medium: 0\n" +
		"low: 0\n" +
		"No findings.\n"

	if got := FormatText(report); got != want {
		t.Fatalf("unexpected no-findings output:\n%s", got)
	}
}
