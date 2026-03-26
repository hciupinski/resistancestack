package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type InitResult struct {
	Created bool
	Added   []string
}

func EnsureDefaultConfig(path string, projectName string, overwrite bool) (InitResult, error) {
	doc, err := DefaultDocument(projectName)
	if err != nil {
		return InitResult{}, err
	}

	if overwrite {
		if err := SaveDocument(path, doc); err != nil {
			return InitResult{}, err
		}
		return InitResult{Created: true}, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := SaveDocument(path, doc); err != nil {
				return InitResult{}, err
			}
			return InitResult{Created: true}, nil
		}
		return InitResult{}, fmt.Errorf("read %s: %w", path, err)
	}

	if strings.TrimSpace(string(raw)) == "" {
		if err := SaveDocument(path, doc); err != nil {
			return InitResult{}, err
		}
		return InitResult{Created: true}, nil
	}

	var existing yaml.Node
	if err := yaml.Unmarshal(raw, &existing); err != nil {
		return InitResult{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(existing.Content) == 0 {
		if err := SaveDocument(path, doc); err != nil {
			return InitResult{}, err
		}
		return InitResult{Created: true}, nil
	}

	added := mergeMissingDefaults(&existing, doc)
	if len(added) == 0 {
		return InitResult{}, nil
	}
	if err := SaveDocument(path, &existing); err != nil {
		return InitResult{}, err
	}
	return InitResult{Added: added}, nil
}

func DefaultDocument(projectName string) (*yaml.Node, error) {
	cfg := Default(projectName)
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal default config: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode default config node: %w", err)
	}
	annotateDefaultComments(&doc)
	return &doc, nil
}
