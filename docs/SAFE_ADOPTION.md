# Safe Adoption on an Existing VPS

This guide is for adopting ResistanceStack on a server that already runs an application.
It separates read-only discovery from host-changing commands so you can stop before any risky step.

## System Requirements

Local machine:

- `resistack` binary installed
- `ssh` client
- private key for the target server
- repository checkout for local inventory and CI detection

Target VPS:

- Linux host with `bash`
- `python3`
- `sudo`
- `systemd`
- `apt-get`
- `sshd`
- optional but expected for full baseline: `ufw`, `fail2ban`, `certbot`, Docker when the app uses containers

Configuration prerequisites:

- `server.host`
- `server.ssh_user`
- `server.private_key_path`
- `server.host_key_checking`
- `deployment.profile`
- app hints such as `app_inventory.compose_paths`, `app_inventory.nginx_paths`, `app_inventory.domains`, and `app_inventory.healthcheck_urls`

## Adoption Flow

### 1. Create Configuration

Read/write scope: local repository only.

```bash
resistack init
```

For guided setup:

```bash
resistack wizard
```

Edit `resistack.yaml` before connecting to production. For production hosts, prefer an explicit environment overlay:

```bash
resistack init
cp resistack.yaml resistack.prod.yaml
```

Then keep production-specific values in `resistack.prod.yaml`.

### 2. Run Doctor

Read-only scope: local checks and remote compatibility checks.

```bash
resistack doctor --all --env prod
```

Use local-only checks when you are not ready to connect to the VPS:

```bash
resistack doctor --local --env prod
```

Do not continue to host hardening until blocking doctor failures are understood. Warnings can be acceptable when they describe optional components your deployment does not use.

### 3. Collect Inventory

Read-only scope: repository and VPS state.

```bash
resistack inventory --env prod
```

If SSH is not ready yet:

```bash
resistack inventory --local --env prod
```

Local mode records host and cloud areas as `not_checked` rather than pretending they are safe.

### 4. Generate Audit Report

Read-only scope: repository and VPS state. Writes report files under `reporting.output_path`.

```bash
resistack audit --env prod
resistack audit --env prod --output html
```

Review these sections before changing the host:

- critical and high findings
- `not_checked` areas
- SSH login path findings
- sudo readiness findings
- TLS and reverse-proxy findings
- remediation plan and auto-remediable flags

### 5. Preview Changes

Read-only scope: prints planned host changes and guardrail results.

```bash
resistack apply host-hardening --dry-run --env prod
```

The dry run shows the generated script and SSH/firewall access model. Treat a dry-run failure as a stop condition.

### 6. Apply Approved Changes

Host-changing scope.

```bash
resistack apply host-hardening --env prod
```

Apply only modules you intend to change. For example, CI workflow generation changes the repository, while host hardening changes the VPS:

```bash
resistack apply ci-security --env prod
resistack apply host-hardening --env prod
```

## Emergency VPS Access

Before applying host hardening, confirm at least one emergency path exists:

- provider console or rescue shell access
- current SSH session kept open until verification finishes
- verified non-root SSH user with `authorized_keys`
- root login decision understood when `disable_root_login=true`
- stable admin source IPs in `host_hardening.ufw_policy.admin_allowlist` when using `allowlist_only`
- recent provider snapshot or backup

Keep one SSH session open while applying host hardening. Open a second terminal and verify the future login path before closing the first one:

```bash
ssh deployer@203.0.113.10 'sudo -n -l && echo OK'
```

## Avoiding SSH Lockout

Use these guardrails before applying:

- Run `resistack deploy-user bootstrap --dry-run` and review the sudo risk profile.
- Bootstrap the future user before disabling root login.
- Run `resistack deploy-user check`.
- Ensure `host_hardening.ssh_hardening.allow_users` contains at least one verified non-root account.
- Keep `host_hardening.ssh_hardening.guard_current_operator=true` unless you have a tested replacement path.
- Use `operator_access_mode=public_hardened` until a stable allowlist is confirmed.
- Use `operator_access_mode=allowlist_only` only with trusted CIDRs in `admin_allowlist`.
- Run `resistack apply host-hardening --dry-run` and read the final SSH rule model.

## Rollback

Rollback scope: host-changing unless `--dry-run` is used.

Preview rollback:

```bash
resistack rollback host --dry-run --env prod
```

Execute rollback:

```bash
resistack rollback host --env prod
```

Host hardening stores backups under `host_hardening.backup_dir`. A backup includes:

- `/etc/ssh/sshd_config`
- `/etc/fail2ban/jail.d/resistack-sshd.local`
- `/etc/ufw` when available
- `ufw status numbered`
- `ufw show added`
- service active/enabled state for `ssh`, `sshd`, `fail2ban`, and `ufw`
- operation metadata with tool version

Rollback restores backed-up files and directories, removes ResistanceStack-managed sudoers snippets, reloads UFW, and restarts only services affected by the restored manifest.

If no backup exists, inspect these areas manually:

- `/etc/ssh/sshd_config`
- `/etc/fail2ban/jail.d/resistack-sshd.local`
- `/etc/ufw`
- provider firewall rules
- provider console or rescue access

## Read-Only vs Changing Commands

Read-only or local-file-only:

- `resistack init`: writes local config
- `resistack wizard`: writes local config
- `resistack doctor --local`: local checks
- `resistack doctor --all`: remote compatibility checks and report output
- `resistack inventory --local`: local repository detection
- `resistack inventory`: remote and repository detection
- `resistack audit --local`: local report
- `resistack audit`: remote and repository report
- `resistack apply host-hardening --dry-run`: preview only
- `resistack rollback host --dry-run`: preview only
- `resistack deploy-user bootstrap --dry-run`: preview only
- `resistack deploy-user check`: remote readiness check

Host-changing:

- `resistack deploy-user bootstrap`
- `resistack apply host-hardening`
- `resistack observability enable`
- `resistack observability disable`
- `resistack rollback host`

Repository-changing:

- `resistack ci generate`
- `resistack apply ci-security`

## MVP Limitations

- ResistanceStack does not deploy the application.
- It does not own application rollback.
- It does not take over public ingress or reverse-proxy configuration.
- Cloud provider firewalls, DNS, backups, WAF, CDN, and external TLS termination are not fully managed in the MVP.
- Local mode cannot validate host security; it marks host and cloud areas as `not_checked`.
- Rollback depends on a previous ResistanceStack host-hardening backup.
- Limited sudo mode is a safer bootstrap path, but operators should still review the generated sudoers profile before production use.
