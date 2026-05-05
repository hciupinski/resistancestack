package doctor

import (
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
		return "", fmt.Errorf("create doctor report directory: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(cfg.Reporting.Format))
	name := "doctor-report.txt"
	content := []byte(FormatText(report))
	if format == config.FormatJSON {
		name = "doctor-report.json"
		raw, err := FormatJSON(report)
		if err != nil {
			return "", fmt.Errorf("marshal doctor report: %w", err)
		}
		content = raw
	}

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return "", fmt.Errorf("write doctor report: %w", err)
	}
	return path, nil
}
