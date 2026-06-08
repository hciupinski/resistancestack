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
	return Document(Default(projectName))
}

func Document(cfg Config) (*yaml.Node, error) {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode config node: %w", err)
	}
	ensureDefaultDocumentFields(&doc)
	annotateDefaultComments(&doc)
	return &doc, nil
}

func ensureDefaultDocumentFields(doc *yaml.Node) {
	if doc == nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return
	}
	observability := mappingValue(root, "observability")
	if observability == nil || observability.Kind != yaml.MappingNode || mappingValue(observability, "grafana_assets_path") != nil {
		return
	}
	observability.Content = append(observability.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "grafana_assets_path"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""},
	)
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
