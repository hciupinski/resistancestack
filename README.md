# ResistanceStack

`ResistanceStack` helps teams harden a VPS, understand what is already running there, add lightweight security visibility, and generate security checks for CI without changing how the application is deployed.

It is built for the common case: one or a few servers, an existing app already running, limited ops capacity, and a need for practical security improvements instead of a large platform rollout.

## What You Get

- host inventory for brownfield environments
- security audit with prioritized findings and remediation hints
- baseline host hardening for SSH, UFW, fail2ban, sudo, security updates, and optional Let's Encrypt issuance for the primary domain
- lightweight observability focused on security and runtime signals
- standalone GitHub Actions workflows for dependency, image, SBOM, and secret scanning
- host rollback for the latest hardening change

## Why Teams Use It

- to improve VPS security without rebuilding the deployment process
- to add security checks to an existing repo without touching deploy workflows
- to understand an inherited server before making changes
- to get a repeatable baseline for small production environments

## How It Works

The normal flow is:

```bash
resistack init
resistack inventory
resistack audit
resistack apply host-hardening
resistack ci generate
resistack observability enable
resistack status
```

`ResistanceStack` works in four modules:

- `inventory-audit`
- `host-hardening`
- `security-observability`
- `ci-security`

You can use them independently. That means you can start with detection only, generate CI only, or enable observability without touching hardening.

## What It Detects

On the server side:

- nginx, Traefik, or no detected proxy
- Docker Compose, plain Docker, or systemd-based runtimes
- open ports and public listeners
- local TLS certificates
- SSH-capable users and sudo users
- UFW and fail2ban state
- common log locations
- running containers

In the repository:

- GitHub Actions workflows
- Node and Next.js projects
- .NET projects
- Dockerfiles and Compose files

## Quick Start

### 1. Create Config

```bash
resistack init
```

This creates `resistack.yaml`.

### 2. Fill In Server Access

At minimum, set:

- `server.host`
- `server.ssh_user`
- `server.private_key_path`
- `server.host_key_checking`

Optional brownfield hints go into:

- `app_inventory.compose_paths`
- `app_inventory.nginx_paths`
- `app_inventory.systemd_units`
- `app_inventory.domains`
- `app_inventory.healthcheck_urls`

See [resistack.example.yaml](/Users/hciupinski/Repositories/cyber_article/ResistanceStack/resistack.example.yaml).

### 3. Detect Current State

```bash
resistack inventory
```

Use this before changing anything. It shows what is already running and what the repo contains.

### 4. Generate a Risk Report

```bash
resistack audit
```

The audit produces findings with:

- severity
- detected value
- risk
- recommendation
- whether the issue can be remediated automatically

Reports are written to `reporting.output_path`.

If the configured `server.ssh_user` does not have passwordless sudo, the audit will report it explicitly and show the exact `sudoers` command to run before host hardening.
If `host_hardening.ssl_certificates.enabled=true`, the audit also checks only the first entry in `app_inventory.domains` and expects a valid local certificate for that primary domain.

### 5. Apply Only What You Want

Examples:

```bash
resistack apply host-hardening
resistack apply security-observability
resistack apply ci-security
resistack apply inventory-audit host-hardening
```

Preview changes first:

```bash
resistack apply host-hardening --dry-run
```

If `host-hardening` detects that the configured SSH user does not have passwordless sudo, it stops immediately and prints the exact commands needed to grant it.
If `host_hardening.ssl_certificates.auto_issue=true`, `host-hardening` will use `certbot certonly --standalone` to issue a missing or expired Let's Encrypt certificate for the primary domain and fail the run if issuance does not succeed.

### 6. Generate Security Workflows

```bash
resistack ci generate
resistack ci validate
```

Generated files:

- `.github/workflows/security-dependencies.yml`
- `.github/workflows/security-containers.yml`
- `.github/workflows/security-sbom.yml`
- `.github/workflows/security-secrets.yml`

These workflows are created alongside existing workflows instead of replacing them.

For GitHub SARIF uploads, use `ci.github.sarif_upload_mode`:

- `auto`: upload only when the repo is configured as public or `ci.github.code_scanning_enabled=true`
- `enabled`: always emit `upload-sarif: true`
- `disabled`: always emit `upload-sarif: false`

Repository hints live under:

- `ci.github.repository_visibility`
- `ci.github.code_scanning_enabled`

### 7. Enable Observability

```bash
resistack observability enable
```

This installs a local baseline for:

- journald signals
- nginx logs
- docker logs
- fail2ban activity
- host metrics and runtime snapshots

Disable it when needed:

```bash
resistack observability disable
```

### 8. Roll Back the Last Host Change

```bash
resistack rollback host
```

Host hardening stores backups of modified system files and can restore the latest applied set.

## Command Reference

```bash
resistack init
resistack inventory
resistack audit
resistack apply [modules...] [--dry-run]
resistack status
resistack ci generate
resistack ci validate
resistack observability enable [--dry-run]
resistack observability disable
resistack rollback host
```

## Configuration Overview

Main sections in `resistack.yaml`:

- `mode`
- `server`
- `host_hardening`
- `app_inventory`
- `observability`
- `ci`
- `reporting`
- `alerts`

Important examples:

- `host_hardening.ssh_hardening`: SSH restrictions and operator guardrails
- `host_hardening.ufw_policy`: default firewall policy, operator access mode, current-session preservation, and optional admin allowlist
- `host_hardening.fail2ban`: ban windows and retry thresholds
- `host_hardening.ssl_certificates`: managed local TLS checks and optional Let's Encrypt auto-issue for `app_inventory.domains[0]`
- `observability.panel_bind`: local bind for the observability view
- `ci.mode`: `warn-only` or `enforced`
- `ci.github.sarif_upload_mode`: `auto`, `enabled`, or `disabled`
- `alerts.thresholds`: brute force, bans, nginx errors, restarts, disk, and certificate thresholds

## Typical Scenarios

### Existing Production VPS

Run:

```bash
resistack inventory
resistack audit
```

Then apply only the parts you approve. This is the safest way to adopt the tool on an existing host.

### Repo With Separate UI and API

If your repo contains paths like `ui/` and `src/Public.Api/`, `resistack ci generate` will create separate security workflows for Node and .NET scanning and add container-focused workflows as well.

### Minimal Baseline Without Deployment Changes

If you want only security improvements around an existing app:

```bash
resistack apply host-hardening
resistack observability enable
resistack ci generate
```

## Development

Run tests with:

```bash
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go test ./...
```
