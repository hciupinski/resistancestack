package inventory

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func DetectComposeFiles(root string, hints []string) ([]string, error) {
	found := map[string]struct{}{}
	for _, hint := range hints {
		if strings.TrimSpace(hint) == "" {
			continue
		}
		if markFile(root, hint, found) {
			continue
		}
	}

	defaults := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"docker-compose.prod.yml",
		"compose.yml",
		"compose.yaml",
	}
	for _, candidate := range defaults {
		_ = markFile(root, candidate, found)
	}

	values := mapKeys(found)
	slices.Sort(values)
	return values, nil
}

func DetectNginxPaths(root string, hints []string) ([]string, error) {
	found := map[string]struct{}{}
	for _, hint := range hints {
		_ = markAny(root, hint, found)
	}
	defaults := []string{"nginx.conf", "infra/nginx", "deploy/nginx", "ops/nginx"}
	for _, candidate := range defaults {
		_ = markAny(root, candidate, found)
	}
	values := mapKeys(found)
	slices.Sort(values)
	return values, nil
}

func DetectSystemdUnits(root string, hints []string) ([]string, error) {
	found := map[string]struct{}{}
	for _, unit := range hints {
		unit = strings.TrimSpace(unit)
		if unit == "" {
			continue
		}
		servicePath := unit
		if !strings.HasSuffix(servicePath, ".service") {
			servicePath += ".service"
		}
		_ = markAny(root, filepath.Join("systemd", servicePath), found)
		_ = markAny(root, filepath.Join("deploy", "systemd", servicePath), found)
		_ = markAny(root, filepath.Join("ops", "systemd", servicePath), found)
	}
	values := mapKeys(found)
	slices.Sort(values)
	return values, nil
}

func DetectGitHubWorkflows(root string) ([]string, error) {
	workflowDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	workflows := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml") {
			workflows = append(workflows, filepath.ToSlash(filepath.Join(".github", "workflows", entry.Name())))
		}
	}
	slices.Sort(workflows)
	return workflows, nil
}

func markFile(root string, candidate string, found map[string]struct{}) bool {
	path := candidate
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, candidate)
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	found[filepath.ToSlash(rel)] = struct{}{}
	return true
}

func markAny(root string, candidate string, found map[string]struct{}) bool {
	path := candidate
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, candidate)
	}
	if _, err := os.Stat(path); err != nil {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	found[filepath.ToSlash(rel)] = struct{}{}
	return true
}

func mapKeys(found map[string]struct{}) []string {
	values := make([]string, 0, len(found))
	for value := range found {
		values = append(values, value)
	}
	return values
}
