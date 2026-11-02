# AI-Assisted Red Teaming Framework

**Red Team Control Center** is a human-in-the-loop application for authorized
security assessments. Import an engagement letter, review a scoped plan, approve
each command, analyze the evidence, and export a versioned HTML report. An
optional AI provider assists planning and analysis; deterministic operation is
available without one.

Use only against systems covered by your authorization. Commands remain subject
to scope, tool, phase and engagement-policy checks, including when an operator
edits a plan or enables lab features.

## What is implemented

- **Engagement setup:** PDF, DOCX, Markdown and text import; reviewed targets,
  allowed/excluded scope, tool restrictions and asset criticality.
- **Phased assessments:** recon, analysis, authorized exploitation,
  post-exploitation and reporting. Eligible follow-up steps are drafted from
  evidence and still require individual approval.
- **Campaign workflows:** opt-in aggressive lab mode adds credential validation,
  lateral movement and impact. Footholds, encrypted loot and host inventory feed
  these planners. Autopilot drafts and proposes; it never approves or executes.
- **Durable execution:** database-backed jobs, cancellation, heartbeat recovery,
  reconnectable redacted output and archived attempts. Local execution and a
  separately configured Kali VM over SSH are supported.
- **Evidence protection:** encrypted execution originals, redacted ordinary
  output, original-evidence hashes and authenticated, audited reveal routes.
- **Consistent publication:** revision checks reject stale plan/phase/analysis
  writes. Analysis commits as one transaction; reports publish immutable
  versions through a database pointer.
- **Operator UI:** phase-aware plan editing, paginated findings and review
  tracking, campaign state, activity details, report history, loading/error
  states, keyboard-accessible controls and responsive layouts.

### Latest reliability changes

Child promotion requires an owned host within the parent's host-wide scope and
outside exclusions. A discovered address or URL/port-only permission cannot
authorize a whole-host child plan. Duplicate concurrent promotions are refused.

Editing later unexecuted work preserves earlier prerequisite findings.
Unchanged saves preserve analysis and the current report; rationale-only edits
preserve analysis and invalidate the current report. Execution-bearing edits
invalidate the earliest changed phase and its dependents.

Scanner originals are encrypted separately from their public projections.
Supported credential formats and known recovered values are redacted before
ordinary display and provider analysis. Redaction is bounded and format-based;
it does not recognize every possible secret in arbitrary text. Planner
credentials use `$$loot:<id>$$` references. Use these references instead of
typing new secrets into executable plan source.

**Upgrading an existing installation:** migration
`0005_protected_workflows` backfills evidence and retires legacy report
downloads. Keep the existing encryption key and upgrade API and worker together.
See [upgrade instructions](docs/protected-evidence-upgrade.md).

## Quick start

### Docker development stack

Install Docker with Compose v2 (the optional env-file syntax needs Compose
2.24 or newer), then run from the repository root:

```sh
docker compose up --build -d
docker compose logs backend
```

Open the UI at **http://localhost:5173**. The API is at
**http://localhost:8000**. If `REDTEAM_API_KEY` is not configured, startup prints
a generated operator key once. Enter it in the UI. Settings, encryption keys
and reports persist in the development data volume.

The stack contains the assessment toolkit, not target applications. Targets must
be reachable from the scanner environment. Use
`host.docker.internal:<port>` for a service exposed on the Docker host when
that address is authorized. A missing scanner or unreachable target is a failed
execution, not evidence that the target is clean.

### Native development

Use Python 3.12 (the CI baseline) and Node.js 22. Install backend dependencies
and start the API from `backend/`:

```sh
cd backend
python -m venv venv
# macOS/Linux
. venv/bin/activate
python -m pip install -r requirements-dev.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

On Windows PowerShell, activate with `.\venv\Scripts\Activate.ps1`, or invoke
`.\venv\Scripts\python.exe` directly. Start the UI in another terminal:

```sh
cd frontend
npm ci
npm run dev
```

Native Python installation does not install scanner binaries. Install the
supported tools separately, use the scanner container, or configure the Kali
VM execution engine. Native startup does not automatically load
`backend/.env`; export variables or use Uvicorn's `--env-file .env` option
when its optional dotenv dependency is installed.

See [deployment and configuration](docs/deployment.md) for production Compose,
operator authentication, encryption-key handling, networking and SSH setup.

## Typical workflow

1. Enter the operator key. Optionally configure your provider and execution VM.
2. Import the engagement letter or register an authorized target manually.
3. Review scope, exclusions, restrictions and exploitation permission.
4. Create an assessment and save the plan. Executed steps retain their position,
   tool, command, phase and enabled state; other steps remain editable when idle.
5. Approve enabled steps in the active phase. Inspect outcomes and redacted
   output; cancellation and failed attempts remain visible.
6. Analyze once every enabled step in the phase has finished. Failures are
   disclosed separately from findings. Review any automatically drafted work.
7. Review findings and campaign evidence, then generate a report when the
   assessment is analyzed. Report history retains previous public versions.

The included [sample engagement letter](JuiceBox_Security_Assessment_Request.pdf)
is a template with environment-specific addresses. Its presence in this
repository does not grant permission to test those systems.

## Architecture

```text
React UI -> FastAPI + operator authentication -> SQLite / Alembic
                  |
                  +-> policy + phase gates -> durable job queue
                  |                            |
                  |                            +-> local scanners or SSH VM
                  |
                  +-> encrypted originals + redacted public evidence
                  +-> analyzer / campaign parsers / optional provider
                  +-> revision-checked findings and immutable report versions
```

In development the API embeds a job runner. Production Compose separates the
API and scanner worker and serves the UI through Nginx at
`http://localhost:8080`, proxying `/api` to the API container.

The policy layer checks supported command arguments and destinations. It is
not a general network egress firewall or a sandbox for every behavior of an
installed scanner. See [security controls and limits](docs/priority_security_fixes.md).

## Validation

The November 2 implementation pass recorded **412 passing backend tests**,
followed by **59 passing focused checks** and **one passing worker-startup
regression**. These runs overlap and must not be added as independent coverage.
The frontend recorded **24 passing tests**, plus successful lint and production
build checks. See [validation details](docs/testing.md).

CI is configured for backend tests, frontend lint/tests/audit/build, Compose
validation and production image builds. A configured job is not proof that the
latest run succeeded: check [GitHub Actions](https://github.com/Sujay2004-real/red-teaming-framework/actions).

## Documentation

| Guide | Purpose |
| --- | --- |
| [Documentation index](docs/README.md) | Current guides, PDFs and historical review records |
| [Deployment](docs/deployment.md) | Setup, configuration, VM execution and recovery |
| [API reference](docs/api-reference.md) | Routes, authentication, examples and conflicts |
| [Backend reference](docs/backend_technical_reference.md) | Modules, persistence, workflow and limits |
| [Evidence upgrade](docs/protected-evidence-upgrade.md) | Migration, legacy reports and audited reveal |
| [Security controls](docs/priority_security_fixes.md) | Enforced checks and practical boundaries |
| [Testing](docs/testing.md) | Checks, recorded results and live evaluation |
| [Frontend guide](frontend/README.md) | UI architecture, development and behavior |
| [Implementation results](docs/implementation_results.md) | Evidence for the project report |
| [Completion checklist](docs/implementation-checklist.md) | Review work and deployment follow-ups |

Licensed under the [MIT License](LICENSE).
