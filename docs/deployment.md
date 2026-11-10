# Deployment and configuration

See the [README](../README.md) for a short startup guide and
[evidence upgrade](protected-evidence-upgrade.md) before updating an installation.

## Development Docker stack

Run `docker compose up --build -d` from the repository root. Development Compose
builds the scanner stage for the backend, exposes API port 8000 and Vite port
5173, and mounts source code. It contains no target services.

`backend/.env` is optional and loaded by development Compose. Copy
[the example](../backend/.env.example) if needed. Data persists in
`data_volume`. `docker compose down` keeps volumes; `down -v` removes them,
including the database, key and reports.

## Production Compose

Set a strong operator key in the shell or a root `.env` file, then start:

```sh
export REDTEAM_API_KEY='replace-with-your-operator-key'
docker compose -f docker-compose.prod.yml up --build -d
```

For PowerShell, set `$env:REDTEAM_API_KEY = 'replace-with-your-operator-key'`
before the same Compose command.

| Service | Behavior |
| --- | --- |
| `api` | Python API image; external-worker mode; read-only root filesystem |
| `worker` | Scanner image and `python worker.py`; writable root filesystem with tmpfs scratch |
| `frontend` | Nginx serving the UI and proxying `/api`; read-only root filesystem |

All services drop Linux capabilities and set `no-new-privileges`, resource
limits and restart policies. The scanner image uses the unprivileged
`redteam` account. Tools needing raw sockets or elevated privileges can be
restricted by this configuration.

The frontend binds to **127.0.0.1:8080**. Production Compose does not publish API
port 8000. API and worker share `production_data`. The API image's healthcheck
calls `/health`; `/ready` separately checks schema readiness and, when
configured, a recent worker heartbeat. The worker has a heartbeat healthcheck.

Production Compose uses shared `/app/data/.secret_key` by default. It does
**not** forward a host `REDTEAM_SECRET_KEY` automatically. To supply it through
your deployment's secret mechanism, explicitly inject the same key into
**both API and worker**.

## Native development

Use Python 3.12 and install `backend/requirements-dev.txt` in a virtual
environment. Start Uvicorn from `backend/` so relative data paths agree:

```powershell
Set-Location -LiteralPath 'C:\path\to\red-teaming-framework\backend'
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Run `npm ci` and `npm run dev` from `frontend/` in another terminal.
Node.js 22 is the CI baseline; the frontend uses React 19 and Vite 8.

Native startup reads environment variables, not `.env` automatically.
Use PowerShell `$env:NAME = 'value'`, shell `export NAME=value`, or Uvicorn's
optional `--env-file` support with its dotenv dependency installed.
Installing Python dependencies does not install scanner binaries.

## Configuration

| Setting | Default or behavior |
| --- | --- |
| `DATABASE_URL` | `sqlite:///./data/redteam.db` |
| `REDTEAM_API_KEY` | Operator key override; otherwise generated once, with only its digest stored |
| `REDTEAM_SECRET_KEY` | Fernet master key; otherwise atomic first-use `data/.secret_key` file |
| `CORS_ALLOW_ORIGINS` | Localhost and 127.0.0.1 on port 5173; production Compose defaults to localhost:8080 |
| `EXECUTION_WORKER_MODE` | `embedded`; production uses `external` |
| `MAX_CONCURRENT_EXECUTIONS` | 2; clamped to 1-8 by the job runner |
| `WORKER_HEARTBEAT_FILE` | Optional; production uses `/app/data/.worker-heartbeat` |
| `VITE_API_URL` | Browser API base; production build uses `/api` |
| `MAX_SUBNET_ADDRESSES` | 256 addresses for primary CIDR target registration |

Provider key, base URL, model, proxy and SSH credentials are configured through
the UI or `PUT /settings`, not provider environment variables. Secret fields
are encrypted; endpoint/model/host settings are ordinary configuration.
A provider needs key, HTTP(S) endpoint and model. Empty secret inputs retain
stored values while the provider endpoint stays the same. Changing or clearing
the endpoint removes the old provider key; submit a new key for a new endpoint.
Trailing slashes do not count as an endpoint change.

### Provider presets in the UI

Open **Settings → AI provider**, choose a provider, paste its API key and click
**Save configuration**. The UI supplies a default model and endpoint. The model
is editable; **Endpoint settings** exposes the base URL. Existing custom
endpoints and saved model choices are preserved on load.

| Preset | Default model | Endpoint reference |
| --- | --- | --- |
| OpenAI (ChatGPT) | `gpt-5.4-mini` | [OpenAI model documentation](https://developers.openai.com/api/docs/models/gpt-5.4-mini) |
| Anthropic (Claude) | `claude-sonnet-4-6` | [Claude OpenAI compatibility](https://platform.claude.com/docs/en/cli-sdks-libraries/libraries/openai-sdk) |
| Google Gemini | `gemini-3.8-flash` | [Gemini OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai) |
| OpenRouter | `openrouter/auto` | [OpenRouter developer platform](https://openrouter.ai/developers) |
| Groq | `openai/gpt-oss-120b` | [Groq OpenAI compatibility](https://console.groq.com/docs/openai) |

Each preset links to its provider's key page. For Anthropic, use a workspace API
key. Model access and API usage depend on the provider account. Choose
**Custom / OpenAI-compatible** for a gateway or another service. Choosing
**Local only (no API key)** and saving clears the provider connection and its
stored key. Presets do not make external requests until an AI feature is used.

The operator key controls application access; the Fernet key decrypts credentials
and evidence. Changing one does not rotate the other.

## Scanner reachability

- `localhost` inside a container refers to that container.
- The scanner service maps `host.docker.internal` to `host-gateway` for
  authorized services on the host.
- LAN/VPN routes, host firewall rules and VM adapters must permit traffic.
- Linux host networking can support lab deployments; replace incompatible
  bridge-network/port settings rather than simply appending it.
- Scope checks do not replace a network firewall.

The Dockerfile pins Nuclei, its templates, ZAP, Exploit-DB and NetExec source
revisions. APT packages, `enum4linux-ng` and NetExec's transitive dependencies
are not all pinned to immutable versions. Verify image builds and live
compatibility for the actual deployment.

## Kali VM execution

Install SSH, tmux and the tools needed for the authorized plan on the VM.
`msfconsole` is VM-only and is not installed in the scanner container.

1. Select **Kali VM over SSH** in Configuration.
2. Enter the SSH address, port, account and password or private-key credentials.
3. Inspect the host-key fingerprint, verify it through a trusted channel and
   save the trusted fingerprint.
4. Test the connection and review tool inventory and host attestation.
5. Approve a scoped step. The framework drives the VM's `redteam` tmux session;
   attach to that session on the VM to observe it.

Missing credentials or an untrusted fingerprint cause refusal, not a silent
switch to local execution. The command allowlist still applies, so arbitrary
`sudo` prefixes are not a general workaround. Configure the VM account and
tool permissions appropriately.

The SSH tmux lock is process-local. Multiple workers must not share the same
pane without a cross-process ownership mechanism. Queue capacity and VM pane
ownership are separate concerns.

## Upgrades and recovery

Drain execution work, back up the database/report volume and retain the matching
encryption key. Update API and worker together. API startup runs Alembic and
evidence backfill; an external worker waits for both schema head and backfill.

Legacy reports remain in history with encrypted originals; ordinary downloads
are unavailable for those restricted versions.
Generate new reports for redacted exports. Previously copied downloads and
backups retain their original contents. See [upgrade details](protected-evidence-upgrade.md).

For `/ready` 503, inspect startup/migration logs and heartbeat. For raw-reveal
409, restore the correct encryption key. Overriding a lost operator key with
`REDTEAM_API_KEY` does not recover an evidence key.

## CI and deployment evidence

[CI](../.github/workflows/ci.yml) configures Python 3.12 tests, frontend checks on
Node 22, Compose validation and API/scanner/frontend image builds. Check the
actual Actions run before claiming an image build succeeded. Live scanners,
SSH, provider connectivity and target reachability remain deployment checks.
