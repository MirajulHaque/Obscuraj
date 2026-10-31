# ObscuraJ

ObscuraJ is a modular OSINT framework for authorized, passive reconnaissance. The current v1.0 implementation provides DNS records, certificate transparency subdomain discovery, Wayback Machine CDX snapshots, Google dork query generation, scan status, JSON results, and HTML reports.

## Supported platforms and verification

- **Verified:** Windows host running Docker Desktop with Linux containers, Docker Engine `linux/amd64`, and Docker Compose v5.6.1. Prior Compose startup, loopback API, scan persistence and exports were verified. The current image build/runtime checks use Python 3.12 on Debian 13 (Trixie).
- **Not verified:** Docker Engine on a Linux host, ARM architectures, native Kali installation, native Windows/macOS execution, or deployment behind a public reverse proxy.

## Docker setup (recommended; no host runtime dependencies)

Host prerequisites are Docker Engine and the Docker Compose plugin (or Docker Desktop with Compose). Python, pip, Bash, `curl`, `jq`, and `dig` do not need to be installed on the host. The image installs and checks the application’s runtime packages and tools. Run from the project root after a clean checkout:

```sh
docker --version
docker compose version
docker compose -f docker/docker-compose.yml up --build -d
```

Open these URLs in a browser to verify health and use the built-in API interface:

- Health: <http://127.0.0.1:19191/health>
- Interactive API: <http://127.0.0.1:19191/docs>

In `/docs`, submit `POST /scan` with a domain you own or are authorized to assess and `mode: "passive"`. Poll `GET /scan/{scan_id}` until it is `completed` or `failed`. Open `GET /report/{scan_id}/download` for HTML or `GET /report/{scan_id}/json` for JSON. No host-side HTTP client is required.

The browser `/docs` workflow is immediately available when the optional API token is unset. If a token is configured, `/docs` is protected along with the scan and report endpoints; use the in-container CLI below, which inherits the Compose token, or access the API with an HTTP client that can send the bearer token.

The optional CLI is also included in the image. This command runs Bash, `curl`, and `jq` inside the container and saves a second HTML copy under the persistent host `data/reports/` directory. Replace the example target with an authorized domain:

```sh
docker compose -f docker/docker-compose.yml exec \
  --user 10001:10001 \
  -e OBSCURAJ_REPORT_DIR=/app/data/reports \
  obscuraj bash /app/cli/obscuraj.sh --target "your-authorized-domain" --mode passive
```

The API is published on host loopback only at `127.0.0.1:19191`. To follow logs or stop the service:

The container starts a root-owned entrypoint to prepare the bind-mounted `data/` directory, then runs the API process as UID 10001 (`obscuraj`). The first start changes ownership of files under `data/` to that container account; file contents are retained. On Linux hosts, this means host-side ownership may become UID 10001.

```powershell
docker compose -f docker/docker-compose.yml logs -f obscuraj
docker compose -f docker/docker-compose.yml stop
```

To remove the stopped container and Compose network while preserving the host data directory:

```powershell
docker compose -f docker/docker-compose.yml down
```

To start again without rebuilding, use `docker compose -f docker/docker-compose.yml up -d`.

Optional API authentication: set `OBSCURAJ_API_TOKEN` in the host environment before starting Compose. Compose passes it to the container. Requests to scan and report endpoints then require `Authorization: Bearer <token>`; `/` and `/health` remain public on loopback. For example, in PowerShell:

```powershell
$env:OBSCURAJ_API_TOKEN = Read-Host "API token"
docker compose -f docker/docker-compose.yml up -d
```

Keep the service loopback-bound unless it is protected by an authenticated TLS reverse proxy. Do not expose an unauthenticated instance to an untrusted network.

No API key is required by the supported modules. DNS uses the container’s configured DNS resolver; subdomain and Wayback modules query public `crt.sh` and Internet Archive endpoints over HTTPS; Google dorks are generated locally and are not submitted to Google. The container needs outbound DNS and HTTPS access for those lookups. Provider availability is outside ObscuraJ’s control, and a failed enabled provider makes the scan fail.

## Native Kali Linux setup (optional, expected, not tested)

The normal Docker workflow above is self-contained with respect to ObscuraJ runtime dependencies. Native installation is a separate, unverified path and requires host Python, pip, Bash, `dig`, `curl`, and `jq`:

```bash
sudo apt update
sudo apt install -y python3 python3-venv bash dnsutils curl jq ca-certificates
git clone <repository-url> obscuraj
cd obscuraj
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m api.main
```

The native API listens on `127.0.0.1:19191`. In another terminal, replace the quoted illustrative placeholder with your authorized fully qualified domain and run the Bash CLI:

```bash
chmod +x cli/obscuraj.sh
./cli/obscuraj.sh --target "your-authorized-domain" --mode passive
```

For a native run with API authentication, export `OBSCURAJ_API_TOKEN` in the server and CLI shells.

## Run a scan

Only `passive` mode is implemented. The browser workflow above is recommended. Host-side HTTP clients are optional; if you use PowerShell `Invoke-RestMethod` or `curl`, use only a target you own or are authorized to assess.

```powershell
$body = @{ target = "your-authorized-domain"; mode = "passive" } | ConvertTo-Json
$scan = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:19191/scan `
  -ContentType "application/json" -Body $body
$scanId = $scan.scan_id
Invoke-RestMethod "http://127.0.0.1:19191/scan/$scanId"
Invoke-RestMethod "http://127.0.0.1:19191/report/$scanId"
```

Poll `GET /scan/{scan_id}` until the status is `completed` or `failed`. A failure in any enabled module keeps the scan status failed. If partial results were saved, report metadata, JSON, and HTML endpoints remain available and identify the failed module.

API endpoints:

- `POST /scan` — submit a target and passive mode.
- `GET /scan/{scan_id}` — status and stored results.
- `GET /report/{scan_id}` — report links and terminal scan status.
- `GET /report/{scan_id}/download` — HTML report.
- `GET /report/{scan_id}/json` — structured JSON result.
- `GET /health` — process health check; it does not check external provider availability.

## Configuration

Edit `config/settings.yaml`:

- `server.port` — API port.
- `security.allowed_targets` — optional domain allowlist; empty allows syntactically valid domains and public IP addresses.
- `security.max_concurrent_scans` — maximum active scan jobs; excess submissions receive HTTP 429.
- `security.request_timeout` — per-request timeout for public OSINT providers.
- `security.scan_timeout` — DNS subprocess timeout, capped at 45 seconds.
- `security.cors_origins` — allowed browser origins.
- `modules.dns.enabled`, `modules.subdomain.enabled`, `modules.wayback.enabled`, `modules.google_dorks.enabled` — enable or disable implemented modules.

The API token is supplied through `OBSCURAJ_API_TOKEN`, not stored in the checked-in settings file. Do not commit real tokens, provider credentials, scan databases, raw logs, or reports.

The Compose service reads the checked-in `config/settings.yaml` from the image. Configuration changes made in a checkout take effect after rebuilding/recreating the service with `docker compose -f docker/docker-compose.yml up --build -d`. `OBSCURAJ_API_TOKEN` is optional; no external provider credentials are required.

## Container contents and persistent data

The image contains the Python runtime and pinned Python packages from `requirements-lock.txt`; pinned Debian packages for Bash, `dig` (`bind9-dnsutils`), `awk` (`mawk`), `curl`, `jq`, CA certificates, core utilities, and `gosu`; and the API, CLI, DNS module, configuration, and reporting code. Image build and runtime checks fail if required executables, Python imports, configuration/module files, or writable data/report directories are missing. There are no bundled wordlists or external template files; the HTML report template is generated by the reporting module.

The Compose bind mount persists data under `./data/` on the host (`/app/data/` in the container): SQLite is `./data/obscuraj.db`, raw module logs are in `./data/raw/`, and generated reports are in `./data/reports/`. `docker compose stop` and `docker compose down` preserve this directory. The container’s startup entrypoint prepares ownership for UID 10001, retaining file contents.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

These are developer test prerequisites, not host requirements for running ObscuraJ. The tests cover target validation, DNS parsing/normalization, SQLite updates, scan failure status, provider response parsing and timeout handling, dork generation, report escaping, and Docker clean-checkout configuration. Provider behavior uses mocks; no live target is scanned. Docker build and runtime checks are run with `docker build --file docker/Dockerfile --tag obscuraj:check .` followed by `docker run --rm obscuraj:check /usr/local/bin/obscuraj-runtime-check`.

## Scope and limitations

- DNS collection queries records using `dig`; it does not attempt zone transfers or active host/service scanning.
- Subdomains come from certificate transparency data. Wayback results come from the Internet Archive CDX API. Both providers can be slow, incomplete, or unavailable; a failed enabled module makes the overall scan fail.
- Google dorks are generated as Google search links. ObscuraJ does not submit or scrape Google queries.
- Results may be stale or rate-limited. Failed scans may still have partial JSON and HTML reports.
- Jobs run in process-local threads. There is no distributed queue, user account system, data retention policy, or active scan mode.
- Shodan and Censys modules are not part of this release.
- Docker runtime dependencies are pinned in `requirements-lock.txt`, the base image digest, and exact Debian package versions. Debian packages resolve from the snapshot dated `2026-10-27`, matching the pinned base image, rather than live apt indexes. Native installation uses the bounded ranges in `requirements.txt`; native dependency versions may change between installs.

Use ObscuraJ only on systems and domains you own or have explicit permission to assess. Public OSINT lookups still disclose the requested domain to the named public providers.

## License and third-party notices

ObscuraJ is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the complete license text. Project-authored source and configuration files identify this license with `SPDX-License-Identifier: Apache-2.0` and include the project copyright notice.

Copyright 2026 Md Mirajul Haque Miraj

ObscuraJ does not include vendored third-party source code. It installs third-party Python packages listed in `requirements.txt` (and pinned for the Docker runtime in `requirements-lock.txt`); those packages remain under their respective upstream licenses and retain their own copyright and attribution notices in their distributions. Review the package metadata and upstream notices when redistributing an installation or image.
