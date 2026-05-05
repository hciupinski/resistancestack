package audit

import (
	"os"
	"path/filepath"
	"strings"
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
				config.SeverityCritical:   1,
				config.SeverityHigh:       2,
				config.SeverityMedium:     0,
				config.SeverityLow:        0,
				config.SeverityNotChecked: 0,
			},
			TopSeverity:   config.SeverityCritical,
			SecurityScore: 40,
		},
		Findings: []Finding{{
			ID:             "host.docker.public-api",
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
		"Security score: 40/100\n" +
		"critical: 1\n" +
		"high: 2\n" +
		"medium: 0\n" +
		"low: 0\n" +
		"not_checked: 0\n" +
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

func TestSave_WritesHTMLReport(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default("demo")
	cfg.Reporting.OutputPath = "reports"
	cfg.Reporting.Format = config.FormatHTML
	report := Report{
		GeneratedAt: time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC),
		Summary: Summary{
			BySeverity:    map[string]int{},
			TopSeverity:   config.SeverityLow,
			SecurityScore: 100,
		},
	}

	path, err := Save(root, cfg, report)
	if err != nil {
		t.Fatalf("save html report: %v", err)
	}
	if path != filepath.Join(root, "reports", "audit-report.html") {
		t.Fatalf("unexpected report path %q", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read html report: %v", err)
	}
	if !strings.Contains(string(raw), "<!doctype html>") {
		t.Fatalf("expected HTML report, got %s", string(raw))
	}
}

func TestFormatText_NoFindings(t *testing.T) {
	report := Report{
		GeneratedAt: time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC),
		Summary: Summary{
			BySeverity: map[string]int{
				config.SeverityCritical:   0,
				config.SeverityHigh:       0,
				config.SeverityMedium:     0,
				config.SeverityLow:        0,
				config.SeverityNotChecked: 0,
			},
			TopSeverity:   config.SeverityLow,
			SecurityScore: 100,
		},
	}

	const want = "" +
		"Audit generated at: 2026-03-25T12:00:00Z\n" +
		"Top severity: low\n" +
		"Security score: 100/100\n" +
		"critical: 0\n" +
		"high: 0\n" +
		"medium: 0\n" +
		"low: 0\n" +
		"not_checked: 0\n" +
		"No findings.\n"

	if got := FormatText(report); got != want {
		t.Fatalf("unexpected no-findings output:\n%s", got)
	}
}

func TestFormatHTML_RendersEscapedSelfContainedReport(t *testing.T) {
	report := Report{
		GeneratedAt: time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC),
		Snapshot: inventory.Snapshot{
			Areas: inventory.Areas{
				Repo:          inventory.AreaStatus{Status: inventory.AreaStatusChecked},
				Host:          inventory.AreaStatus{Status: inventory.AreaStatusChecked},
				CloudExternal: inventory.AreaStatus{Status: inventory.AreaStatusNotChecked, Reason: "local mode"},
			},
		},
		Summary: Summary{
			BySeverity: map[string]int{
				config.SeverityCritical:   0,
				config.SeverityHigh:       1,
				config.SeverityMedium:     0,
				config.SeverityLow:        0,
				config.SeverityNotChecked: 1,
			},
			TopSeverity:   config.SeverityHigh,
			SecurityScore: 80,
		},
		Findings: []Finding{
			{
				ID:             "host.ufw.disabled",
				Severity:       config.SeverityHigh,
				Description:    "UFW <disabled>",
				Module:         "host-hardening",
				DetectedValue:  "inactive",
				Risk:           "unfiltered ingress",
				Recommendation: "run apply",
				AutoRemediable: true,
			},
			{
				ID:             "cloud_external.not_checked",
				Severity:       config.SeverityNotChecked,
				Description:    "Cloud checks were not executed.",
				Module:         "cloud-external",
				DetectedValue:  "local mode",
				Risk:           "external state missing",
				Recommendation: "run remote audit",
				AutoRemediable: false,
			},
		},
		Remediation: []Remediation{{
			Module: "host-hardening",
			Reason: "1 auto-remediable finding(s)",
			Steps:  []string{"run apply"},
		}},
	}

	got := FormatHTML(report)
	for _, want := range []string{
		"<!doctype html>",
		"<style>",
		"Security score",
		"80/100",
		"Checked Areas",
		"Remediation Plan",
		"Not Checked",
		"auto-remediable: true",
		"UFW &lt;disabled&gt;",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected HTML to contain %q, got %s", want, got)
		}
	}
	for _, forbidden := range []string{"<script", "https://", "http://", "cdn"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("expected self-contained safe HTML without %q, got %s", forbidden, got)
		}
	}
}
