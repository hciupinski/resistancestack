package audit

import (
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

type Finding struct {
	ID             string `json:"id"`
	Module         string `json:"module"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	DetectedValue  string `json:"detected_value"`
	Risk           string `json:"risk"`
	Recommendation string `json:"recommendation"`
	AutoRemediable bool   `json:"auto_remediable"`
}

type Remediation struct {
	Module string   `json:"module"`
	Reason string   `json:"reason"`
	Steps  []string `json:"steps"`
}

type Summary struct {
	BySeverity  map[string]int `json:"by_severity"`
	TopSeverity string         `json:"top_severity"`
}

type Report struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Snapshot    inventory.Snapshot `json:"snapshot"`
	Summary     Summary            `json:"summary"`
	Findings    []Finding          `json:"findings"`
	Remediation []Remediation      `json:"remediation"`
}

var severityOrder = map[string]int{
	config.SeverityNotChecked: 0,
	config.SeverityLow:        1,
	config.SeverityMedium:     2,
	config.SeverityHigh:       3,
	config.SeverityCritical:   4,
}
