package inventory

import (
	"encoding/json"
	"fmt"
	"time"

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
	snapshot.Areas = remoteAreas()
	repo, err := collectRepoInfo(root, cfg)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Repo = repo
	return snapshot, nil
}

func CollectLocal(cfg config.Config, root string) (Snapshot, error) {
	repo, err := collectRepoInfo(root, cfg)
	if err != nil {
		return Snapshot{}, err
	}

	runtimeKind := "unknown"
	switch {
	case len(repo.ComposeFiles) > 0:
		runtimeKind = "docker-compose"
	case len(repo.SystemdUnits) > 0:
		runtimeKind = "systemd"
	}

	return Snapshot{
		CollectedAt: time.Now().UTC(),
		Areas: Areas{
			Repo: AreaStatus{
				Status: AreaStatusChecked,
			},
			Host: AreaStatus{
				Status: AreaStatusNotChecked,
				Reason: "local mode does not open an SSH connection to the host",
			},
			CloudExternal: AreaStatus{
				Status: AreaStatusNotChecked,
				Reason: "local mode only inspects repository files",
			},
		},
		Host: HostInfo{
			Hostname: AreaStatusNotChecked,
			OS:       AreaStatusNotChecked,
			Kernel:   AreaStatusNotChecked,
		},
		Proxy: ProxyInfo{
			Kind:  AreaStatusNotChecked,
			Notes: []string{"not checked in local mode"},
		},
		Runtime:  RuntimeInfo{Kind: runtimeKind, ComposeFiles: repo.ComposeFiles, SystemdUnits: repo.SystemdUnits},
		UFW:      ServiceState{Status: AreaStatusNotChecked},
		Fail2ban: ServiceState{Status: AreaStatusNotChecked},
		Observability: ObservabilityInfo{
			Status: AreaStatusNotChecked,
		},
		Repo: repo,
	}, nil
}

func remoteAreas() Areas {
	return Areas{
		Repo:          AreaStatus{Status: AreaStatusChecked},
		Host:          AreaStatus{Status: AreaStatusChecked},
		CloudExternal: AreaStatus{Status: AreaStatusChecked},
	}
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
