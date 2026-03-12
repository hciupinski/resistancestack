package stack

import (
	"errors"
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/ci"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/deploy"
	"github.com/hciupinski/resistancestack/internal/preflight"
	"github.com/hciupinski/resistancestack/internal/remote"
)

func Deploy(cfg config.Config, wd string, dryRun bool, out io.Writer, errOut io.Writer) error {
	warnings, errs := preflight.CheckLocal(cfg, wd, !dryRun)
	printWarnings(out, warnings)
	printErrors(errOut, "preflight error", errs)
	if len(errs) > 0 {
		return errors.New("preflight checks failed")
	}

	artifacts, err := resolveArtifacts(cfg, wd)
	if err != nil {
		return err
	}

	release := deploy.NewRelease(cfg.ProjectName, newReleaseID())
	script := deploy.BuildProvisionScript(cfg, release)
	if dryRun {
		fmt.Fprintf(out, "Dry run mode.\nrelease: %s\ncompose: %s\n", release.ID, artifacts.ComposePath)
		if artifacts.EnvPath != "" {
			fmt.Fprintf(out, "env: %s\n", artifacts.EnvPath)
		}
		fmt.Fprintln(out, "Generated provisioning script:")
		fmt.Fprintln(out, script)
		return nil
	}

	target := newTarget(cfg)
	if err := remote.Run(target, "echo resistack-ssh-ok", out, errOut); err != nil {
		return fmt.Errorf("ssh connectivity check failed: %w", err)
	}

	if err := remote.RunScript(target, prepareRemoteReleaseScript(release), out, errOut); err != nil {
		return fmt.Errorf("prepare remote release: %w", err)
	}
	if err := remote.Upload(target, release.RemoteComposePath, artifacts.ComposeRaw); err != nil {
		return fmt.Errorf("upload compose file: %w", err)
	}
	if len(artifacts.EnvRaw) > 0 {
		if err := remote.Upload(target, release.RemoteEnvPath, artifacts.EnvRaw); err != nil {
			return fmt.Errorf("upload env file: %w", err)
		}
	}

	if err := remote.RunScript(target, script, out, errOut); err != nil {
		return err
	}

	if cfg.CI.GitHubActions {
		workflowPath, created, err := ci.EnsureSecurityWorkflow(wd)
		if err != nil {
			return err
		}
		if created {
			fmt.Fprintf(out, "Generated CI security workflow at %s\n", workflowPath)
		} else {
			fmt.Fprintf(out, "CI security workflow already exists at %s\n", workflowPath)
		}
	}

	fmt.Fprintf(out, "Deploy completed for project %q with release %s.\n", cfg.ProjectName, release.ID)
	return nil
}

func prepareRemoteReleaseScript(release deploy.Release) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
sudo install -d -m 0755 %s %s %s
sudo chown -R "${USER}":"${USER}" %s
`, shellQuote(release.RemoteRoot), shellQuote(release.RemoteRoot+"/releases"), shellQuote(release.RemoteReleaseDir), shellQuote(release.RemoteRoot))
}
