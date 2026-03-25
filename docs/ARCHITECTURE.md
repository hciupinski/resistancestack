# ResistanceStack Architecture v2

## Product boundary

ResistanceStack v2 is a security baseline platform.

It sits next to an existing application and deployment process.
It does not own:

- application deployment
- application release rollback
- application Compose uploads
- reverse proxy takeover
- public TLS ingress takeover

Success is measured as:

- safer host baseline
- better inventory and security posture visibility
- additional independent CI checks

## Modules

### `inventory-audit`

- remote brownfield host detection over SSH
- local repo detection for workflows and technologies
- risk report with `critical/high/medium/low`
- remediation plan with auto-remediable flags

### `host-hardening`

- SSH hardening
- UFW baseline
- fail2ban baseline
- optional Let's Encrypt issuance for the primary configured domain
- deploy user and sudo checks
- file backups before system changes
- rollback of the last host operation

This module does not manage nginx application config or app containers beyond read-only inspection.

### `security-observability`

- local `systemd` timer for snapshot collection
- journald, nginx, docker, and fail2ban signal gathering
- container restart, disk pressure, and certificate inventory checks
- local-only HTTP file view bound outside the public app ingress

### `ci-security`

- GitHub Actions workflow generation and validation
- standalone security workflows
- no overwrite of existing deploy workflows
- warn-only or enforced modes

## Control flow

- `init`: creates a v2 baseline config
- `inventory`: collects host and repo state
- `audit`: evaluates findings and writes a report
- `apply`: applies selected modules
- `status`: summarizes host state and audit posture
- `ci generate`: writes standalone security workflows
- `ci validate`: checks whether generated workflows are present and current
- `observability enable|disable`: manages the local observability baseline
- `rollback host`: restores the last host-hardening backup set

## Data flow

### Remote host

The CLI connects over SSH and gathers:

- host identity
- active proxy hints
- runtime hints
- exposed ports
- TLS certificate inventory
- SSH and sudo users
- UFW and fail2ban state
- log locations
- running containers

### Local repo

The CLI inspects:

- `.github/workflows`
- Node or Next.js projects
- .NET projects
- Dockerfiles and Compose files
- optional inventory hints from `resistack.yaml`

## Legacy scope

Managed deploy capabilities from v1 are legacy only and are intentionally out of the active command model in v2.
