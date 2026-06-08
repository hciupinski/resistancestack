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
		case d.Name() == "requirements.txt" || d.Name() == "pyproject.toml" || d.Name() == "manage.py":
			project := detectPythonProject(root, rel)
			profile.PythonProjects = appendPythonProject(profile.PythonProjects, project)
		case d.Name() == "composer.json" || d.Name() == "artisan" || d.Name() == "wp-config.php":
			project := detectPHPProject(root, rel)
			profile.PHPProjects = appendPHPProject(profile.PHPProjects, project)
		case d.Name() == "index.html":
			if isStaticSitePath(rel) {
				profile.StaticSites = append(profile.StaticSites, filepath.ToSlash(filepath.Dir(rel)))
			}
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
	slices.SortFunc(profile.PythonProjects, func(a, b PythonProject) int { return strings.Compare(a.Path, b.Path) })
	slices.SortFunc(profile.PHPProjects, func(a, b PHPProject) int { return strings.Compare(a.Path, b.Path) })
	profile.StaticSites = dedupeSorted(profile.StaticSites)
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

func detectPythonProject(root string, relPath string) PythonProject {
	projectDir := filepath.Dir(relPath)
	if filepath.Base(relPath) == "manage.py" {
		projectDir = filepath.Dir(relPath)
	}
	if projectDir == "." {
		projectDir = "."
	}
	manifest := filepath.ToSlash(relPath)
	framework := detectPythonFramework(root, projectDir)
	return PythonProject{
		Path:      filepath.ToSlash(projectDir),
		Manifest:  manifest,
		Framework: framework,
	}
}

func detectPythonFramework(root string, projectDir string) string {
	if fileExists(filepath.Join(root, projectDir, "manage.py")) {
		return "django"
	}
	for _, manifest := range []string{"requirements.txt", "pyproject.toml"} {
		raw, err := os.ReadFile(filepath.Join(root, projectDir, manifest))
		if err != nil {
			continue
		}
		text := strings.ToLower(string(raw))
		if strings.Contains(text, "fastapi") {
			return "fastapi"
		}
		if strings.Contains(text, "django") {
			return "django"
		}
	}
	return "python"
}

func detectPHPProject(root string, relPath string) PHPProject {
	projectDir := filepath.Dir(relPath)
	if projectDir == "." {
		projectDir = "."
	}
	manifest := filepath.ToSlash(relPath)
	framework := detectPHPFramework(root, projectDir)
	return PHPProject{
		Path:      filepath.ToSlash(projectDir),
		Manifest:  manifest,
		Framework: framework,
	}
}

func detectPHPFramework(root string, projectDir string) string {
	switch {
	case fileExists(filepath.Join(root, projectDir, "wp-config.php")):
		return "wordpress"
	case fileExists(filepath.Join(root, projectDir, "artisan")):
		return "laravel"
	}

	raw, err := os.ReadFile(filepath.Join(root, projectDir, "composer.json"))
	if err != nil {
		return "php"
	}
	text := strings.ToLower(string(raw))
	switch {
	case strings.Contains(text, "laravel/framework"):
		return "laravel"
	case strings.Contains(text, "johnpbloch/wordpress") || strings.Contains(text, "wordpress"):
		return "wordpress"
	default:
		return "php"
	}
}

func appendPythonProject(projects []PythonProject, project PythonProject) []PythonProject {
	for idx, existing := range projects {
		if existing.Path != project.Path {
			continue
		}
		if existing.Framework == "python" || project.Framework == "django" {
			projects[idx] = project
		}
		return projects
	}
	return append(projects, project)
}

func appendPHPProject(projects []PHPProject, project PHPProject) []PHPProject {
	for idx, existing := range projects {
		if existing.Path != project.Path {
			continue
		}
		if existing.Framework == "php" || project.Framework == "wordpress" {
			projects[idx] = project
		}
		return projects
	}
	return append(projects, project)
}

func isStaticSitePath(relPath string) bool {
	dir := filepath.ToSlash(filepath.Dir(relPath))
	switch dir {
	case ".", "public", "dist", "build", "site":
		return true
	default:
		return strings.HasPrefix(dir, "public/") || strings.HasPrefix(dir, "dist/") || strings.HasPrefix(dir, "build/")
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dedupeSorted(values []string) []string {
	slices.Sort(values)
	result := []string{}
	var previous string
	for _, value := range values {
		if value == previous {
			continue
		}
		result = append(result, value)
		previous = value
	}
	return result
}
