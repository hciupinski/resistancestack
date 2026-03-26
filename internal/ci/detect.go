package ci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func DetectTech(root string) (TechProfile, error) {
	profile := TechProfile{}

	workflowDir := filepath.Join(root, ".github", "workflows")
	if entries, err := os.ReadDir(workflowDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if isYAML(entry.Name()) {
				profile.ExistingWorkflows = append(profile.ExistingWorkflows, entry.Name())
			}
		}
		slices.Sort(profile.ExistingWorkflows)
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".next" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		switch {
		case d.Name() == "package.json":
			project, ok := detectNodeProject(path, rel)
			if ok {
				profile.NodeProjects = append(profile.NodeProjects, project)
			}
		case strings.HasSuffix(d.Name(), ".csproj"):
			profile.DotnetProjects = append(profile.DotnetProjects, filepath.ToSlash(rel))
		case strings.HasPrefix(d.Name(), "Dockerfile"):
			profile.Dockerfiles = append(profile.Dockerfiles, filepath.ToSlash(rel))
		case d.Name() == "docker-compose.yml" || d.Name() == "docker-compose.yaml" || d.Name() == "compose.yml" || d.Name() == "compose.yaml":
			profile.ComposeFiles = append(profile.ComposeFiles, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return TechProfile{}, err
	}

	slices.SortFunc(profile.NodeProjects, func(a, b NodeProject) int { return strings.Compare(a.Path, b.Path) })
	slices.Sort(profile.DotnetProjects)
	slices.Sort(profile.Dockerfiles)
	slices.Sort(profile.ComposeFiles)
	return profile, nil
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

func detectNodeProject(absPath string, relPath string) (NodeProject, bool) {
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return NodeProject{}, false
	}
	var pkg struct {
		Name         string            `json:"name"`
		Dependencies map[string]string `json:"dependencies"`
		DevDeps      map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return NodeProject{}, false
	}

	framework := "node"
	if _, ok := pkg.Dependencies["next"]; ok {
		framework = "nextjs"
	} else if _, ok := pkg.DevDeps["next"]; ok {
		framework = "nextjs"
	}

	projectDir := filepath.ToSlash(filepath.Dir(relPath))
	return NodeProject{
		Path:      projectDir,
		Package:   pkg.Name,
		Framework: framework,
	}, true
}
