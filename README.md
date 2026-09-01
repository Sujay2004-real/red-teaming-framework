# AI-Assisted Red Teaming Framework

**Red Team Control Center** — a human-in-the-loop platform for conducting *authorized*
security assessments. You hand it a client engagement letter; it reads the scope and
rules of engagement, drafts a non-destructive assessment plan, and runs each scanner
command **only after you explicitly approve it**. Results are correlated into scored,
prioritized findings and delivered as an HTML report that cites the engagement.

> ⚠️ **Authorized use only.** This tool is built for laboratory environments and
> engagements you are contractually permitted to test. Every command is gated by a
> strict allowlist policy engine and requires explicit human approval. Do not point it
> at systems you do not own or have written authorization to assess.

---

## Table of contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [The assessment workflow](#the-assessment-workflow)
- [Security model](#security-model)
- [Technology stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Running with Docker (recommended)](#running-with-docker-recommended)
- [Running locally for development](#running-locally-for-development)
- [Configuration](#configuration)
- [Using the application](#using-the-application)
- [Testing](#testing)
- [Project structure](#project-structure)
- [API reference](#api-reference)

---

## What it does

Traditional security tooling either automates everything (unsafe, unauditable) or leaves
the operator to run every command by hand (slow, error-prone). This framework sits in
between: an **agent crew** proposes the work, but a human approves every action, and a
policy engine guarantees that nothing outside the authorized scope can ever run.

Key capabilities:

- **Engagement-letter import** — drop in a client request as PDF, Word, Markdown, or
  text; the framework extracts targets, authorized scopes, per-target tool restrictions,
  declared asset criticality, objectives, and out-of-scope / prohibited lists —
  deterministically, without needing an AI provider.
- **AI-assisted planning** — with an (optional) OpenAI-compatible provider configured, it
  drafts an assessment plan tailored to the objective; every step is filtered through the
  policy engine before it reaches you. With no provider, it falls back to a safe default
  plan.
- **Allowlist policy enforcement** — a per-tool flag allowlist, scope-checked targets, and
  an approved-resolver list. Anything not explicitly permitted **fails closed**.
- **Human-in-the-loop execution** — each approved command runs in a sandboxed async
  subprocess with timeouts, output caps, optional proxy support, and a full audit trail.
- **Findings analysis** — tool output is correlated into deduplicated findings with
  transparent severity, risk, priority, and confidence scores (AI or deterministic
  fallback).
- **Client-ready reporting** — a self-contained HTML report that cites the engagement
  reference, objectives, and every command that was run.

---

## Architecture

```
┌──────────────────────┐         HTTP/JSON          ┌───────────────────────────────┐
│   Frontend (React)   │ ◀────────────────────────▶ │        Backend (FastAPI)      │
│   Vite dev server    │                            │                               │
│   :5173              │                            │  main.py   — REST API         │
└──────────────────────┘                            │  database.py — ORM + migrate  │
                                                     │  models.py — request schemas  │
                                                     │                               │
                                                     │  modules/                     │
                                                     │   engagement_parser  ← PDFs   │
                                                     │   planner   ─┐                │
                                                     │   policy_engine  (allowlist)  │
                                                     │   executor  ─┤ subprocess     │
                                                     │   analyzer  ─┘                │
                                                     │   reporter  → HTML            │
                                                     │   secret_store (Fernet)       │
                                                     │  :8000                        │
                                                     └───────────────┬───────────────┘
                                                                     │ runs scanners against
                                                          ┌──────────┴───────────┐
                                                          ▼                      ▼
                                                  ┌───────────────┐     ┌────────────────┐
                                                  │  Juice Shop   │     │      DVWA      │
                                                  │  lab :3000    │     │   lab :8080    │
                                                  └───────────────┘     └────────────────┘
```

### Backend modules

| File | Responsibility |
|------|----------------|
| `main.py` | FastAPI app: targets, assessments, execution, analysis, reporting, settings, uploads |
| `database.py` | SQLAlchemy models, SQLite auto-migration, one-time credential-encryption migration |
| `models.py` | Pydantic request models with input validation and bounds |
| `modules/engagement_parser.py` | Deterministic parser: engagement letter text → structured brief |
| `modules/planner.py` | Assessment-plan generation (AI provider or built-in default), policy-filtered |
| `modules/policy_engine.py` | **The security core** — allowlist command validation, scope + resolver checks |
| `modules/executor.py` | Async subprocess execution with timeouts, output caps, env sandboxing, proxy |
| `modules/analyzer.py` | Findings extraction, deduplication, and risk/priority/confidence scoring |
| `modules/reporter.py` | Jinja2 HTML report rendering |
| `modules/secret_store.py` | Fernet encryption-at-rest for provider credentials |

### Frontend

A single-page React 19 app (`frontend/src/App.jsx`) that visualizes the agent crew,
the assessment pipeline, the parsed brief, the editable command plan, findings, and the
execution audit trail. It never holds secrets and reads only server-confirmed state.

---

## The assessment workflow

1. **Read the letter** — import the client engagement PDF. The parser extracts targets,
   scopes, criticality, tool restrictions, objectives, and rules of engagement.
2. **Register targets** — each authorized target is stored with its scopes, criticality,
   and any tools the client's letter restricts for it.
3. **Draft the plan** — the planner proposes commands for a target's objective; each is
   validated against the policy engine. Restricted tools never make it onto the list.
4. **Approve & execute** — you review and approve each command individually. Approved
   commands run in a sandboxed subprocess; everything is logged.
5. **Analyze** — once every enabled step has run, outputs are correlated into scored,
   deduplicated findings.
6. **Report** — generate a client-ready HTML report citing the engagement and evidence.

---

## Security model

The framework is deliberately conservative — safety is enforced in code, not convention:

- **Allowlist, fail-closed policy engine.** Every flag each tool may receive is enumerated
  per tool. Anything not enumerated is refused. File-write, output-redirect, body-sending,
  and connection-retargeting flags are deliberately excluded.
- **Scope enforcement.** Every command must contain an explicit target inside the target's
  authorized scopes (hostname suffix match or CIDR membership). DNS resolvers are validated
  separately against in-scope hosts plus a well-known public-resolver allowlist.
- **Human-in-the-loop.** No command runs without an explicit, per-step approval request
  carrying `approved: true`. The plan is locked once execution begins.
- **Client engagement letter outranks everything.** Per-target tool restrictions parsed
  from the letter are enforced at approval time, above both the AI and the operator's plan.
- **Sandboxed execution.** Scanners are launched via `create_subprocess_exec` (never a
  shell — so shell metacharacters carry no injection risk), inherit only a minimal
  environment, are killed on timeout or client disconnect, and have their output bounded.
- **No default AI provider.** The endpoint, model, and API key are supplied by the operator
  and stored **encrypted at rest** (Fernet). No environment variable can seed a credential,
  and secrets are never returned by the API — only booleans indicating whether they are set.

---

## Technology stack

**Backend:** Python 3.10 · FastAPI · Uvicorn · SQLAlchemy · SQLite · Pydantic · Jinja2 ·
cryptography (Fernet) · pypdf · python-docx · pytest

**Frontend:** React 19 · Vite

**Scanners:** nmap · traceroute · dig · nslookup · curl · whatweb · sslscan · nuclei

**Infrastructure:** Docker · Docker Compose · OWASP Juice Shop & DVWA (deliberately
vulnerable lab targets)

---

## Prerequisites

- **Docker Desktop** with Compose v2 (recommended path — bundles all scanner tools and both
  lab targets), **or**
- **Python 3.10+** and **Node.js 20+** for local development. Note that full command
  execution needs the scanner binaries (nmap, nuclei, …), which are installed inside the
  backend Docker image; a bare local backend on Windows can drive the UI and the AI/parser
  features but will not have the scanners on `PATH`.

---

## Running with Docker (recommended)

From the project root:

```bash
docker compose up --build
```

This starts four services:

| Service | URL | Purpose |
|---------|-----|---------|
| Frontend | http://localhost:5173 | The control center UI |
| Backend API | http://localhost:8000 | FastAPI (docs at `/docs`) |
| Juice Shop | http://localhost:3000 | Vulnerable web app (lab target) |
| DVWA | http://localhost:8080 | Vulnerable web app (lab target) |

The SQLite database and the credential key persist in a named Docker volume, so they
survive container rebuilds.

> **Note on host/origin config:** by default the stack runs entirely on `localhost`, so a
> fresh clone works with no changes. To reach the UI from another device on your LAN, set
> `VITE_API_URL` and `CORS_ALLOW_ORIGINS` to your machine's IP (in your shell or a root
> `.env` file) before `docker compose up` — no need to edit `docker-compose.yml`:
>
> ```bash
> # example: LAN access from other devices
> VITE_API_URL=http://192.168.1.50:8000 \
> CORS_ALLOW_ORIGINS=http://192.168.1.50:5173 \
> docker compose up --build
> ```

To stop and remove the containers:

```bash
docker compose down          # keep the data volume
docker compose down -v       # also delete the database + key volume
```

---

## Running locally for development

### Backend

```bash
cd backend
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The API is now at http://localhost:8000 (interactive docs at http://localhost:8000/docs).
On first start it creates `data/redteam.db` and a local `data/.secret_key`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Vite serves the UI at http://localhost:5173. If your backend is not at
`http://localhost:8000`, set `VITE_API_URL` (see below).

> **Local-dev caveats:**
> - The UI works identically at `http://localhost:5173` and `http://127.0.0.1:5173` —
>   both origins are allowed by the backend's default CORS policy. If you reach the UI
>   from another device or hostname, set both `VITE_API_URL` (where the browser finds
>   the backend) and `CORS_ALLOW_ORIGINS` (which browser origins the backend accepts).
> - A bare local backend on Windows has no scanner binaries on `PATH`, so
>   **Approve & execute** will fail with a clear error; the UI, letter import, planning,
>   and analysis features all work regardless. Use Docker for full command execution.
> - The UI polls `/health` and shows a banner when the backend is unreachable, and every
>   button explains itself while its request is in flight — a disabled button is always
>   either busy or waiting on you, never silently broken.

---

## Configuration

### Backend environment variables

Copy `backend/.env.example` to `backend/.env` and adjust as needed. All values are optional
and have safe defaults.

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `sqlite:///./data/redteam.db` | Database location |
| `REDTEAM_SECRET_KEY` | *(generated)* | Master key for encrypting stored credentials. Set it explicitly if `data/` is not persistent, or stored secrets become undecryptable when the key regenerates. |
| `CORS_ALLOW_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated browser origins allowed to call the API |

### Frontend environment variable

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITE_API_URL` | `http://localhost:8000` | Base URL the UI calls |

### AI provider (optional)

The AI provider is **not** configured through environment variables — it is entered in the
**Configuration** panel of the UI (Base URL, model name, API key for any OpenAI-compatible
`/chat/completions` endpoint) and stored encrypted. With no provider configured, the
framework runs entirely on its deterministic planner and analyzer.

---

## Using the application

1. **(Optional) Configure an AI provider** in the Configuration panel. Skip this to run in
   deterministic (local) mode.
2. **Import the client's letter** — drag the engagement PDF onto the *Read the client's
   letter* panel. Review the parsed targets, scopes, criticality, and rules of engagement.
3. **Set up from the letter** — one click registers every target and drafts a plan for
   each, or register targets individually. You can also add a target manually.
4. **Review the command plan** for an assessment. Edit, enable/disable, or add commands.
   Save the plan.
5. **Approve & execute** each command. Watch the execution audit trail populate.
6. **Analyze results** once every enabled step has run.
7. **Generate the report** and download the HTML deliverable.

A `JuiceBox_Security_Assessment_Request.pdf` sample letter is included at the project root
for testing the import flow. (`make_client_request_pdf.py` regenerates it.)

---

## Testing

The backend has a pytest suite covering the analyzer, planner, policy engine, secret store,
request models, engagement parser, and the end-to-end API workflow.

```bash
cd backend
# Windows:
venv\Scripts\python.exe -m pytest -q
# macOS/Linux:
python -m pytest -q
```

`pytest.ini` sets `testpaths = test_*.py` so pytest never parses the `[IMPLEMENTATION]`
segment of the project path as parametrization syntax.

---

## Project structure

```
.
├── backend/
│   ├── main.py                     # FastAPI application & endpoints
│   ├── database.py                 # ORM models, migrations, secret migration
│   ├── models.py                   # Pydantic request models
│   ├── modules/
│   │   ├── engagement_parser.py    # Engagement letter → structured brief
│   │   ├── planner.py              # Assessment plan generation
│   │   ├── policy_engine.py        # Allowlist command validation
│   │   ├── executor.py             # Sandboxed subprocess execution
│   │   ├── analyzer.py             # Findings correlation & scoring
│   │   ├── reporter.py             # HTML report rendering
│   │   ├── secret_store.py         # Credential encryption at rest
│   │   └── templates/
│   │       └── report_template.html
│   ├── test_*.py                   # pytest suite
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 # The entire single-page UI
│   │   ├── App.css
│   │   └── main.jsx
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml              # backend + frontend + Juice Shop + DVWA
├── JuiceBox_Security_Assessment_Request.pdf   # sample engagement letter
├── make_client_request_pdf.py      # regenerates the sample letter
└── data/                           # SQLite DB + generated reports (gitignored)
```

---

## API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness check |
| `GET` | `/capabilities` | Public list of enabled capabilities and their tools |
| `GET` / `PUT` | `/settings` | Read / update provider & proxy configuration (secrets write-only) |
| `POST` | `/requirements/extract` | Extract plain text from an uploaded requirements document |
| `POST` | `/engagement/parse` | Parse an uploaded engagement letter into a structured brief |
| `POST` / `GET` | `/targets/` | Create / list authorized targets |
| `POST` / `GET` | `/assessments/` | Create / list assessments |
| `GET` | `/assessments/{id}` | Full assessment detail (plan, executions, findings) |
| `PUT` | `/assessments/{id}/plan` | Replace the command plan (before execution begins) |
| `POST` | `/assessments/{id}/execute` | Approve & execute a single plan step |
| `POST` | `/assessments/{id}/analyze` | Correlate executed outputs into findings |
| `POST` | `/assessments/{id}/report` | Generate the HTML report |
| `GET` | `/reports/{id}` | Download a generated report |

---

*Built for authorized laboratory environments only. Human approval is required before
every command.*
