# ResistanceStack

**Build like the Resistance. Deploy like survival depends on it.**

`ResistanceStack` to narzędzie dla zespołów, które nie mają czasu na ręczne gaszenie pożarów bezpieczeństwa na VPS.
CLI `resistack` automatyzuje obronę: hardening hosta, firewall, fail2ban, reverse proxy, TLS, status i alerty.

To klimat ruchu oporu z uniwersum *Terminatora*: mały zespół, realne zagrożenie, szybkie i skuteczne wdrożenie.

## Problem

Internet nie czeka, aż skończysz feature.
Boty skanują publiczne serwery 24/7, a małe zespoły zwykle nie mają dedykowanego SecOps.

Na bazie przeanalizowanych logów (realny przypadek VPS):
- `189,182` prób nieudanego logowania SSH
- `112,671` prób z nieprawidłowymi userami
- `6,386` podejrzanych eventów HTTP
- `245` błędów upstream

`ResistanceStack` adresuje dokładnie ten poziom ryzyka w modelu „minimum operacji, maksimum efektu”.

## Co dostajesz

- `resistack.yaml` jako pojedynczy kontrakt konfiguracji
- `resistack scaffold` do wygenerowania lokalnego startera (`resistack.local.yaml`, `docker-compose.app.yml`, `.env.app.example`)
- automatyczny provisioning przez SSH z host key checking
- SSH hardening (`PermitRootLogin no`, `PasswordAuthentication no`)
- UFW z domyślnym `deny incoming` i guardrailem chroniącym operatora przed odcięciem własnego IP
- fail2ban (`sshd`, `recidive`) + webhook alerty ban/unban
- release-based deploy aplikacji z uploadem `docker-compose.app.yml` i rollbackiem do poprzedniego release
- Nginx reverse proxy dla aplikacji i panelu statusu
- Let's Encrypt TLS (`certbot`) + auto-reload przy renew
- dashboard statusu (`Uptime Kuma`) pod `/_resistack/status/` z Basic Auth
- `resistack status` z licznikami SSH/auth, probe HTTP i upstream 5xx względem progów z configu
- `resistack rotate-secrets` do rotacji hasła dashboardu
- `resistack uninstall` do bezpiecznego zdjęcia stacka z hosta
- opcjonalne security workflow do GitHub Actions

## Jak to działa

```bash
resistack init myapp
resistack validate
resistack deploy
```

Tryb bezpiecznego podglądu przed wdrożeniem:

```bash
resistack deploy --dry-run
```

Status operacyjny i sygnały bezpieczeństwa:

```bash
resistack status
```

Lokalne wygenerowanie gotowego zestawu plików startowych:

```bash
resistack scaffold myapp
```

## Dla kogo

- zespoły 1-10 osób deployujące aplikacje na 1 VPS
- startupy i projekty SaaS z ograniczonym budżetem operacyjnym
- developerzy bez głębokiego doświadczenia w utrzymaniu serwerów

## Dla kogo nie

- duże środowiska multi-region/multi-cluster
- organizacje potrzebujące pełnego SOC/SIEM enterprise
- workflow wyłącznie Kubernetes-first (to jest roadmapa poza v1)

## Kluczowa konfiguracja

Pliki wzorcowe:
- `resistack.example.yaml`
- `resistack.local.yaml` (generowany przez `resistack scaffold`)

Najważniejsze pola:
- `server.*`: dostęp SSH do VPS
- `server.host_key_checking`: `strict` albo `accept-new`
- `domain.fqdn`: domena kierująca na publiczny IP serwera
- `app.compose_file`: plik Compose aplikacji wysyłany na serwer
- `app.env_file`: opcjonalny plik env dla Compose
- `app.upstream_url`: backend aplikacji podpinany pod `/`
- `tls.enabled`: włącz/wyłącz automatyzację certyfikatu
- `tls.email`: email wymagany przez Let's Encrypt
- `tls.staging`: `true` dla certyfikatów testowych
- `alerts.webhook_url`: endpoint alertów bezpieczeństwa
- `dashboard.basic_auth.*`: ochrona panelu statusowego

## Wymagania dla TLS produkcyjnego

- `domain.fqdn` musi wskazywać na publiczny IP VPS
- porty `80/tcp` i `443/tcp` muszą być osiągalne z Internetu
- na pierwszy deploy zalecane `tls.staging: true`, potem `false`

## Szybki start (Go)

```bash
go run ./cmd/resistack help
go run ./cmd/resistack scaffold myapp
go run ./cmd/resistack init myapp
go run ./cmd/resistack validate
go run ./cmd/resistack deploy --dry-run
```

## Status projektu

Gotowe:
- `init`, `validate`, `deploy`, `status`
- provisioning hosta + reverse proxy + TLS
- release-based deploy aplikacji i rollback do poprzedniego release
- status z progami i log-based security counters
- webhook alerty fail2ban
- `rotate-secrets` i `uninstall`

Roadmapa:
- automatyczne alerty z progów HTTP/upstream bez wywoływania `resistack status`
- backup/restore polityk hosta przy pełnym rollbacku
- wsparcie dla innych distro niż `apt`

## Development

- Go 1.26.0 (sprawdzone)
- testy:

```bash
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/go-mod go test ./...
```

---

**ResistanceStack**: kiedy świat sieci zachowuje się jak Skynet, Twoja infrastruktura powinna zachowywać się jak ruch oporu.
