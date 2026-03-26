package inventory

import (
	"encoding/json"
	"fmt"

	"github.com/hciupinski/resistancestack/internal/ci"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

func Collect(cfg config.Config, root string) (Snapshot, error) {
	target := remote.NewTarget(cfg)

	raw, err := remote.CaptureScript(target, buildRemoteInventoryScript(cfg))
	if err != nil {
		return Snapshot{}, err
	}

	var snapshot Snapshot
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode inventory: %w", err)
	}
	repo, err := collectRepoInfo(root, cfg)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Repo = repo
	return snapshot, nil
}

func collectRepoInfo(root string, cfg config.Config) (RepoInfo, error) {
	profile, err := ci.DetectTech(root)
	if err != nil {
		return RepoInfo{}, err
	}
	workflows, err := DetectGitHubWorkflows(root)
	if err != nil {
		return RepoInfo{}, err
	}
	composeFiles, err := DetectComposeFiles(root, cfg.AppInventory.ComposePaths)
	if err != nil {
		return RepoInfo{}, err
	}
	nginxPaths, err := DetectNginxPaths(root, cfg.AppInventory.NginxPaths)
	if err != nil {
		return RepoInfo{}, err
	}
	systemdUnits, err := DetectSystemdUnits(root, cfg.AppInventory.SystemdUnits)
	if err != nil {
		return RepoInfo{}, err
	}

	technologies := []string{}
	if len(profile.NodeProjects) > 0 {
		technologies = append(technologies, "node")
		for _, project := range profile.NodeProjects {
			if project.Framework == "nextjs" {
				technologies = append(technologies, "nextjs")
				break
			}
		}
	}
	if len(profile.DotnetProjects) > 0 {
		technologies = append(technologies, ".net")
	}
	if len(profile.Dockerfiles) > 0 || len(profile.ComposeFiles) > 0 || len(composeFiles) > 0 {
		technologies = append(technologies, "docker")
	}
	technologies = dedupeStrings(technologies)

	return RepoInfo{
		GitHubWorkflows: workflows,
		ComposeFiles:    composeFiles,
		NginxPaths:      nginxPaths,
		SystemdUnits:    systemdUnits,
		Technologies:    technologies,
		TechProfile:     profile,
	}, nil
}
