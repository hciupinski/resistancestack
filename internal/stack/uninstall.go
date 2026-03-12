package stack

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/remote"
)

func Uninstall(cfg config.Config, retainData bool, out io.Writer, errOut io.Writer) error {
	target := newTarget(cfg)
	if err := remote.RunScript(target, buildUninstallScript(cfg, retainData), out, errOut); err != nil {
		return err
	}

	fmt.Fprintf(out, "Uninstall completed for project %q (retain-data=%t).\n", cfg.ProjectName, retainData)
	return nil
}

func buildUninstallScript(cfg config.Config, retainData bool) string {
	dataCleanup := ""
	if !retainData {
		dataCleanup = fmt.Sprintf("sudo rm -rf %s\n", shellQuote("/opt/resistack/"+cfg.ProjectName))
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
PROJECT=%s
ROOT_DIR=%s

CURRENT_DIR="${ROOT_DIR}/current"
if [ -L "${CURRENT_DIR}" ]; then
  CURRENT_DIR="$(readlink -f "${CURRENT_DIR}")"
fi

if [ -f "${ROOT_DIR}/shared/docker-compose.security.yml" ]; then
  pushd "${ROOT_DIR}/shared" >/dev/null
  sudo docker compose --project-name "${PROJECT}-security" -f docker-compose.security.yml down || true
  popd >/dev/null
fi

if [ -f "${CURRENT_DIR}/docker-compose.app.yml" ]; then
  APP_ARGS=(--project-name "${PROJECT}-app" -f "${CURRENT_DIR}/docker-compose.app.yml")
  if [ -f "${CURRENT_DIR}/.env.app" ]; then
    APP_ARGS+=(--env-file "${CURRENT_DIR}/.env.app")
  fi
  sudo docker compose "${APP_ARGS[@]}" down || true
fi

sudo rm -f "/etc/nginx/sites-available/resistack-${PROJECT}.conf"
sudo rm -f "/etc/nginx/sites-enabled/resistack-${PROJECT}.conf"
sudo rm -f "/etc/nginx/resistack-${PROJECT}.htpasswd"
sudo nginx -t && sudo systemctl reload nginx || true
%s
`, shellQuote(cfg.ProjectName), shellQuote("/opt/resistack/"+cfg.ProjectName), dataCleanup)
}
