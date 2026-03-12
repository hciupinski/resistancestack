# ResistanceStack Architecture v1

## Product boundary

v1 is a reusable security platform for small apps on one VPS.
It is not an application template for a specific framework.

## Control plane

- Local Go CLI (`resistack`) runs on developer machine
- CLI connects over SSH to target VPS
- CLI uploads release artifacts and applies idempotent provisioning steps

## Data plane (target host)

- Reverse proxy (hardened defaults)
  - `/` proxied to `app.upstream_url`
  - `/_resistack/status/` proxied to local Uptime Kuma
  - optional TLS termination via Let's Encrypt (`certbot` webroot)
- App containers (owned by user project)
  - `docker-compose.app.yml` uploaded as a release artifact
  - `current` symlink points at the active release
  - failed deploy rolls back to previous release when available
- Security controls:
  - firewall baseline
  - SSH hardening
  - fail2ban jails (`sshd`, `recidive`)
  - webhook alerts on fail2ban ban/unban events
- Lightweight observability:
  - status dashboard
  - health, incident, certificate, SSH auth, probe, and upstream error summary

## Command model

- `init`: create default config
- `validate`: validate config quality
- `deploy`: run preflight and provisioning
- `status`: read health and security signal summary
- `rotate-secrets`: rotate keys and tokens
- `uninstall`: remove platform with optional data retention

## Security profiles

- `balanced` (default): safe baseline for most small projects
- `strict`: lower tolerance and tighter limits
- `lenient`: compatibility-focused mode
