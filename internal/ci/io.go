package ci

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hciupinski/resistancestack/internal/config"
)

func Preview(root string, cfg config.Config) ([]WorkflowFile, error) {
	return expectedWorkflows(root, cfg)
}

func Generate(root string, cfg config.Config) ([]string, error) {
	workflows, err := expectedWorkflows(root, cfg)
	if err != nil {
		return nil, err
	}
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workflow directory: %w", err)
	}

	written := make([]string, 0, len(workflows))
	for _, wf := range workflows {
		if err := os.WriteFile(wf.Path, []byte(wf.Content), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", wf.Path, err)
		}
		written = append(written, wf.Path)
	}
	return written, nil
}

func Validate(root string, cfg config.Config) (ValidationResult, error) {
	workflows, err := expectedWorkflows(root, cfg)
	if err != nil {
		return ValidationResult{}, err
	}

	result := ValidationResult{}
	for _, wf := range workflows {
		raw, err := os.ReadFile(wf.Path)
		if err != nil {
			if os.IsNotExist(err) {
				result.Missing = append(result.Missing, wf.Name)
				continue
			}
			return ValidationResult{}, fmt.Errorf("read %s: %w", wf.Path, err)
		}
		if string(raw) != wf.Content {
			result.Outdated = append(result.Outdated, wf.Name)
		}
	}
	return result, nil
}
