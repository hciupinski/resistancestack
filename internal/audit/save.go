package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
)

func Save(root string, cfg config.Config, report Report) (string, error) {
	dir := cfg.Reporting.OutputPath
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}
	format := strings.ToLower(strings.TrimSpace(cfg.Reporting.Format))
	name := "audit-report.txt"
	content := []byte(FormatText(report))
	if format == config.FormatJSON {
		name = "audit-report.json"
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal audit report: %w", err)
		}
		content = raw
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return "", fmt.Errorf("write audit report: %w", err)
	}
	return path, nil
}
