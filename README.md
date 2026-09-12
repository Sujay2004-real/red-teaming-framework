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
- [Assessing real-world targets](#assessing-real-world-targets)
- [Kali VM execution engine (attacker-VM mode)](#kali-vm-execution-engine-attacker-vm-mode)
- [Using the application](#using-the-application)
- [Manual effort vs. the framework](#manual-effort-vs-the-framework)
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

- **Full engagement lifecycle** — the assessment walks the whole pentest workflow with the
  phases visible in the UI stepper: **scoping & authorization → reconnaissance &
  enumeration → vulnerability analysis → exploitation → post-exploitation → reporting**.
  Each phase's plan is drafted from the previous phase's findings, so an exploitation step
  can only exist because the analysis actually produced something to verify. Analyzing a
  phase **auto-drafts the next one**: the moment the recon output is correlated, the
  exploitation plan is already in front of you — still policy-gated, still per-step
  approved; the operator just no longer has to press Draft to see it.
- **Letter-gated controlled exploitation** — when (and only when) the client's engagement
  letter explicitly authorizes controlled vulnerability verification for a target, the
  framework drafts and runs bounded proof-of-concepts: `sqlmap` verification with
  conservative flags, `curl` PoC payloads against the letter's declared verification
  endpoints, offline `searchsploit` lookups, and `msfconsole` scanner modules on the
  attacker-VM engine. Without that authorization the policy engine refuses every
  exploit-grade command with the reason — before a human is even asked.
- **Engagement-letter import** — drop in a client request as PDF, Word, Markdown, or
  text; the framework extracts targets, authorized scopes, per-target tool restrictions,
  declared asset criticality, verification endpoints, exploitation authorization,
  objectives, and out-of-scope / prohibited lists — deterministically, without needing
  an AI provider.
- **Subnet discovery** — a CIDR target (e.g. `172.28.0.0/24`) gets a two-step
  discovery plan: an `nmap` live-host sweep followed by a targeted port/version sweep,
  with every finding attributed to the host it came from. Primary network targets
  are bounded to 256 addresses by default (`MAX_SUBNET_ADDRESSES`); anything larger
  should be split into smaller authorized ranges. The assessment detail and
  `GET /assessments/{id}/discovered-hosts` expose the resulting host inventory,
  but discovered hosts still require separate registration and approval for deeper
  testing.
- **AI-assisted planning** — with an (optional) OpenAI-compatible provider configured, it
  drafts an assessment plan tailored to the objective; every step is filtered through the
  policy engine before it reaches you. With no provider, it falls back to a safe default
  plan.
- **Adaptive next-step proposals** — mid-engagement, ask what to do *next* given what has
  actually been observed. The framework condenses the findings and the audit trail into a
  bounded engagement state, proposes **ranked** candidate steps with a rationale and the
  findings that drove each one, and hands them to you to pick from. Anything already
  executed is withheld, every candidate is policy-checked before you see it, and the ones
  the policy engine **refused** are shown too, with their reasons. Nothing is saved until
  you add it to the plan and approve it — the loop is adaptive, the authority is still
  yours.
- **Automatic recommendation loop** — beyond the on-demand proposals, every finished
  command schedules a proposal batch automatically: the backend computes what to do next
  from the observed state, persists the batch (including the policy engine's refusals) as
  engagement evidence, and the UI surfaces it the moment the command's output lands. It
  proposes; it never acts — a batch becomes plan steps only through the ordinary
  plan-save path, and a per-engagement budget caps the automatic batches so a run of
  failing commands cannot manufacture an endless suggestion stream.
- **Attack-path reasoning** — findings that share an origin (or an affected parameter)
  are correlated into attack paths: ranked chains showing how a missing header, an
  exposed service and a verified injection on the same origin combine, with the
  exploitation verdicts carried through. Each path gets a one-paragraph explanation —
  grounded, when an AI provider is configured: every finding id a narrative cites is
  verified to exist, and a hallucinated citation falls back to the deterministic
  explanation. Paths appear in the client report's "Attack paths" section.
- **Allowlist policy enforcement** — a per-tool flag allowlist, scope-checked targets, and
  an approved-resolver list. Anything not explicitly permitted **fails closed**.
- **Human-in-the-loop execution** — each approved command runs in a sandboxed async
  subprocess with timeouts, output caps, optional proxy support, and a full audit trail.
- **Findings analysis & verification** — tool output is correlated into deduplicated
  findings with transparent severity, risk, priority, and confidence scores (AI or
  deterministic fallback). Exploitation-phase results are linked back to the findings
  they prove, so the report separates "a scanner matched a signature" from "exploitation
  demonstrated it".
- **Client-ready reporting** — a self-contained HTML report that cites the engagement
  reference, objectives, phase progress, verification evidence, and every command that
  was run.

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
                                                  │  Any          │     │  The Kali      │
                                                  │  authorized   │     │  attacker VM   │
                                                  │  real target  │     │  (VM execution │
                                                  │ (LAN/VPN/host)│     │   mode, via    │
                                                  │               │     │   SSH + tmux)  │
                                                  └───────────────┘     └────────────────┘
```

### Backend modules

| File | Responsibility |
|------|----------------|
| `main.py` | FastAPI app: targets, assessments, execution, phase planning, analysis, reporting, settings, uploads |
| `database.py` | SQLAlchemy models, SQLite auto-migration, one-time credential-encryption migration |
| `models.py` | Pydantic request models with input validation and bounds |
| `modules/phases.py` | The engagement phase model shared by backend and UI (order, gates, tool tiers) |
| `modules/engagement_parser.py` | Deterministic parser: engagement letter text → structured brief (incl. exploitation authorization) |
| `modules/planner.py` | Recon-plan generation (AI provider or built-in default), policy-filtered |
| `modules/exploit_planner.py` | Findings → exploitation / post-exploitation steps, every step policy-validated |
| `modules/next_steps.py` | Adaptive next-step proposals: engagement-state digest → ranked, policy-checked candidates |
| `modules/policy_engine.py` | **The security core** — allowlist command validation, scope + resolver checks, exploitation gate, msfconsole script validation |
| `modules/executor.py` | Async subprocess execution with timeouts, output caps, env sandboxing, proxy |
| `modules/ssh_executor.py` | Kali attacker-VM engine: paramiko SSH + tmux, per-run attestation |
| `modules/analyzer.py` | Findings extraction, deduplication, scoring, verification linking |
| `modules/reporter.py` | Jinja2 HTML report rendering (phases, verification section) |
| `modules/secret_store.py` | Fernet encryption-at-rest for provider credentials |

### Frontend

A single-page React 19 app (`frontend/src/App.jsx`) that visualizes the agent crew,
the assessment pipeline, the parsed brief, the editable command plan, findings, and the
execution audit trail. It never holds secrets and reads only server-confirmed state.

---

## The assessment workflow

The engagement walks six phases, all visible in the UI's phase stepper:

1. **Scoping & authorization** — import the client engagement PDF. The parser extracts
   targets, scopes, criticality, tool restrictions, verification endpoints, exploitation
   authorization, objectives, and rules of engagement. Register each authorized target.
2. **Reconnaissance & enumeration** — draft the plan (two ways to enter: **from the
   letter**, or **with your own prompt** over picked targets; both go through the same
   policy review and per-target letter restrictions). Approve and execute each command
   individually; everything is logged with a live terminal view.
3. **Vulnerability analysis** — once every enabled step of the phase has run, outputs are
   correlated into scored, deduplicated findings. The next phase's plan is drafted FROM
   these findings.
4. **Exploitation** *(letter-gated)* — if the client's letter authorizes controlled
   verification for the target, the framework drafts proof-of-concept steps from the
   findings: offline `searchsploit` lookups for versioned fingerprints, `sqlmap`
   parameter verification for web endpoints, `curl` PoC payloads for the letter's
   declared verification endpoints, and `msfconsole` scanner modules (attacker-VM
   engine only). Every step still needs explicit approval; on targets without the
   authorization, the policy engine refuses each one with the reason.
5. **Post-exploitation** *(bounded)* — for verified findings only: a single benign
   verification record per flaw (DBMS banner, current database user) — exactly what the
   letter permits. No privilege escalation, no persistence, no lateral movement, no
   enumeration.
6. **Reporting** — a client-ready HTML report citing the engagement, phase progress,
   the verification evidence, and every command that was run.

---

## Adaptive next-step proposals (human-approved)

A plan drafted before the first command ran cannot know what the target would turn out to
be. Mid-engagement, the **Propose next steps** button asks the framework what to do given
what has *actually* been observed so far:

1. The findings, the executed commands and their outcomes, and the letter's restrictions
   are condensed into a bounded **engagement state** (capped findings, capped command
   list, ANSI escapes stripped) — the engagement's working memory, kept small enough to
   stay legible as the run grows.
2. With a provider configured, that state is sent once for a ranked list of candidate
   steps. Without one, the same question is answered from the framework's own
   deterministic generators for that phase, **minus everything already run** — so the
   no-provider path proposes work you could have reached by hand, not a weaker parallel
   path.
3. Every candidate is checked against the same policy engine, the same authorized scopes,
   and the same letter-gated exploitation rule the approval step uses. Candidates the
   engine refuses are **shown with their reasons** rather than hidden.
4. A candidate whose command has already been executed is withheld — the audit trail is
   the memory, so the engagement cannot loop over surfaces it has already covered.
5. Survivors are displayed with their rationale, their risk, and **which finding drove
   each one**. Tick the ones you want, add them to the plan, edit them freely, and save.

Three properties are worth stating plainly, because they are the point:

- **It proposes; it never acts.** The endpoint persists nothing. Proposals become plan
  steps only through the ordinary plan-save path, so executed-step immutability, phase
  tagging and plan validation keep living in exactly one place.
- **The AI cannot widen your authority.** Scopes come from the target record and the
  policy engine re-checks every command, so the worst a model can produce is a *useless*
  proposal — never an out-of-scope step.
- **Proposals are confined to the phase in progress**, because that is the only phase
  whose new steps can be analyzed as a unit. `vuln_analysis` and `reporting` own no plan
  steps and say so, naming the door to use instead.

> **Note on where the AI now reads from.** Tool output reaches the model prompt, and nmap
> banners and HTTP headers are written by the *target*. That is a target-controlled
> prompt-injection channel, and it is handled as one: tool-derived text is stripped of
> control characters and confined to a delimited untrusted block with a standing
> instruction that it is data, never a direction. It is still shown, because it is
> evidence — what it cannot do is change what is authorized, which is decided by the
> target record and the policy engine.

---

The framework is deliberately conservative — safety is enforced in code, not convention:

- **Operator authentication.** Every API route except `/health` requires the operator's
  API key (`X-API-Key` header). The key is either chosen through `REDTEAM_API_KEY` (the
  path for Docker, CI and the scripted flows) or generated on first start, printed to the
  backend console exactly once, and stored only as a SHA-256 digest — a copied database
  file does not carry the credential. The UI prompts for it the first time the backend
  answers 401 and remembers it per browser.
- **Allowlist, fail-closed policy engine.** Every flag each tool may receive is enumerated
  per tool. Anything not enumerated is refused. File-write, output-redirect,
  connection-retargeting, and shell/interactive flags are deliberately excluded
  (sqlmap's `--os-shell`/`--sql-shell`/`--dump`, msfconsole's payload/handler options,
  searchsploit's browser/copy flags, and ZAP's active-scan, config-file and daemon-option
  flags among them).
- **Letter-gated exploitation.** Exploitation-grade commands — `sqlmap`, `msfconsole`,
  or `curl` carrying a request body — are refused unless the client's engagement letter
  explicitly authorizes controlled verification for that target. The gate applies at
  plan time, at phase-draft time, and at approval time, always with the reason.
- **Bounded verification.** Post-exploitation steps retrieve a single benign record per
  verified flaw (DBMS banner / current user). No privilege escalation, persistence,
  lateral movement, or data enumeration is possible through the policy engine.
- **Scope enforcement.** Every command must contain an explicit target inside the target's
  authorized scopes (hostname suffix match, CIDR membership, or — for a CIDR target —
  the requested range being a subnet of an authorized network). DNS resolvers are
  validated separately against in-scope hosts plus a well-known public-resolver
  allowlist. msfconsole resource scripts are validated statement by statement: module
  tree allowlist, option-key allowlist, and every `RHOSTS` value scope-checked.
- **Human-in-the-loop.** No command runs without an explicit, per-step approval request
  carrying `approved: true`. Executed steps are immutable in the plan (the audit trail
  cannot be rewritten); unexecuted steps and later phases stay editable.
- **Client engagement letter outranks everything.** Per-target tool restrictions parsed
  from the letter are enforced at approval time, above both the AI and the operator's plan.
- **A read-only advisor.** The next-step proposal endpoint can never run, save or approve
  anything: it returns candidates, and the human accepts them through the same plan-save
  path as a hand-typed step. Its refusals are returned too, so the guardrail's work is
  visible instead of silent.
- **Sandboxed execution.** Scanners are launched via `create_subprocess_exec` (never a
  shell — so shell metacharacters carry no injection risk), inherit only a minimal
  environment, are killed on timeout or client disconnect, and have their output bounded.
- **No default AI provider.** The endpoint, model, and API key are supplied by the operator
  and stored **encrypted at rest** (Fernet). No environment variable can seed a credential,
  and secrets are never returned by the API — only booleans indicating whether they are set.

---

## Technology stack

**Backend:** Python 3.10 · FastAPI · Uvicorn · SQLAlchemy · SQLite · Pydantic · Jinja2 ·
cryptography (Fernet) · paramiko (Kali VM execution engine) · pypdf · python-docx · pytest

**Frontend:** React 19 · Vite

**Scanners & verification tools:** nmap · traceroute · dig · nslookup · curl · whatweb ·
sslscan · nuclei · OWASP ZAP (passive baseline — the active scanner's flags are refused
by the policy engine by design) · sqlmap · searchsploit (offline Exploit-DB) · msfconsole
(attacker-VM engine only)

**Infrastructure:** Docker · Docker Compose

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

The stack starts two services:

| Service | URL | Purpose |
|---------|-----|---------|
| Frontend | http://localhost:5173 | The control center UI |
| Backend API | http://localhost:8000 | FastAPI (docs at `/docs`) |

The Compose stack runs the **assessment toolkit alone** — exactly what you would
run on an assessor's laptop. Targets are whatever you are authorized to assess
(see [Assessing real-world targets](#assessing-real-world-targets)); the backend
container reaches hosts on your machine's network, and `host.docker.internal`
is mapped for you in case you want to assess a service on the host itself.

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
| `REDTEAM_API_KEY` | *(generated)* | The operator key every route except `/health` requires. Generated and printed to the console once on first start when unset; set it explicitly for Docker, CI and the scripted flows. || `REDTEAM_SECRET_KEY` | *(generated)* | Master key for encrypting stored credentials. Set it explicitly if `data/` is not persistent, or stored secrets become undecryptable when the key regenerates. |
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

## Assessing real-world targets

The framework is **not limited to the Docker lab targets**. The scanners run
inside the backend container, which reaches the outside world through the
host's network — so any device your machine can reach (a LAN host, a VPN
segment, an internet-facing system you are authorized to test) is a valid
target:

1. Run the toolkit: `docker compose up` (no lab profile needed).
2. Register the real target in **Add authorized target** (host, host:port, or a CIDR
   like `192.168.1.0/24` for a discovery sweep, scopes, criticality) — or import an
   engagement letter that names it; the parser handles hostnames, IPs, and subnets.
3. From there the flow is identical: plan → review → approve each command →
   analysis → report. The policy engine, per-step human approval, rate limits,
   audit trail, scoring and reporting all apply exactly the same.

**Network notes:**
- The backend container must be able to reach the target — test with
  `docker compose exec backend curl -I http://target:port` if unsure.
- Private DNS names only resolve if your host's resolver knows them; use IPs
  or public names when in doubt.
- On Linux, `network_mode: host` on the backend service places the scanners
  directly on the host network for accurate LAN subnet scans.
- `host.docker.internal` (your own machine) can be registered as a target —
  it is outside the compose network and still fully governed, which is a
  quick way to verify the whole flow end to end.
- A CIDR target runs discovery only (live hosts + exposed services); the sweep's
  findings name each host individually, but a host it finds is not authorized for
  deeper assessment until you register it separately with the client's say-so.

**Honest scope statement:** this is a *non-destructive scanning and governance*
framework — reconnaissance, fingerprinting, header/TLS audits and
template-driven checks, each behind an allowlist policy and a human approval.
It is deliberately **not** an exploitation framework; that restraint is what
makes it safe to point at client systems.

## Kali VM execution engine (attacker-VM mode)

For engagements where the assessment must demonstrably run from a real attacker
machine — or simply to prove live, in front of an audience, that results are
not pre-staged — the framework can execute every approved command **inside a
Kali Linux VM**, driven from the backend on the Windows host:

- The backend (running natively on Windows) connects to the VM over SSH.
- Each approved command is **typed into a tmux session on the VM** — attach
  the VM's console with `tmux attach -t redteam` and watch the framework type
  and run the command on the VM's own screen, exactly as a human operator
  would.
- The same output streams into the framework's live terminal and is stored in
  the audit trail, together with a per-step **attestation**: the VM's hostname,
  OS, kernel, and the SSH **host-key fingerprint** — evidence that cannot be
  produced without connecting to that machine, and that appears identically on
  every step of the run and in the generated report.
- The policy engine, per-step human approval, scope checks, rate limits and
  audit trail apply exactly as in local/Docker mode; only *where* the command
  runs changes.

### One-time setup inside the Kali VM

On the VM's host-only adapter (e.g. `192.168.56.15` on the standard
`192.168.56.0/24` VirtualBox network):

```bash
sudo apt update
sudo apt install -y openssh-server tmux nmap traceroute dnsutils whatweb sslscan nuclei curl
sudo systemctl enable --now ssh
```

`traceroute` needs raw sockets, so either enable root SSH on the lab VM
(`PermitRootLogin yes` in `/etc/ssh/sshd_config`) and use `root` as the
framework user, or keep the `kali` user and allow the scanners passwordless
sudo (`visudo`: `kali ALL=(ALL) NOPASSWD: /usr/bin/traceroute, ...` — commands
are then typed as `sudo traceroute …`).

### Running an engagement in VM mode

1. Start the backend natively (no Docker needed — the scanners live in the VM):
   `cd backend; venv\Scripts\activate; uvicorn main:app --port 8000`, and the
   frontend with `npm run dev` in `frontend/`.
2. In the UI's **Configuration** panel set *Execution mode* to
   **Kali VM over SSH**, enter host/port/username/password (the password is
   Fernet-encrypted at rest and never returned by the API), and click
   **Test connection** — the panel shows the VM's real identity and a
   checklist of the installed tools.
3. On the VM console run `tmux attach -t redteam` (the session is created by
   the test) and leave it on screen.
4. Import the engagement letter, approve steps — and watch each command appear
   in the VM's terminal while the UI streams the same output. Each step's audit row
   carries a `ran on Kali VM user@host` badge with the full attestation.

If anything about the VM misbehaves mid-engagement, switch *Execution mode* back to
**Local / Docker container** — nothing else changes.


## Manual effort vs. the framework

The default deterministic plan for one web target runs **8 commands**
(service/version discovery, path tracing, name resolution, full header capture,
technology fingerprinting, TLS audit, a passive ZAP baseline crawl, and
rate-limited template checks). A competent tester doing the same coverage by hand
would:

| Manual tester | The framework |
|---|---|
| Recall and type 15–20 commands with the right flags, per target | Drafts all 8 policy-checked steps in seconds, per target |
| Watch each command's output and note findings as they scroll past | Streams every output into a live terminal and persists all of it |
| Re-read outputs, dedupe findings across tools, look up remediations | Correlates, dedupes, scores and explains every finding automatically |
| Spend 1–3 hours writing the report | Generates a cited, prioritized HTML report in seconds |
| Nothing prevents a typo hitting an out-of-scope host | Policy engine refuses out-of-scope and prohibited commands before they run |

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

**Starting without a letter:** the *New assessment* panel has a second tab, *Your own
prompt*. Pick one or more registered targets, write the engagement in your own words
(e.g. "enumerate services and audit the HTTP security headers on the web application"), and
the framework drafts a policy-checked plan per target. With an AI provider configured,
your prompt steers the drafted commands; without one, each target gets the standard
deterministic plan. Per-target scopes, criticality and letter restrictions apply exactly
as in the letter-driven flow, and every command still waits for your approval.

A sample engagement letter (`JuiceBox_Security_Assessment_Request.pdf`) is included
at the project root so the import flow can be tried immediately: it exercises every
field the parser understands — multiple targets with separate scopes and criticality,
per-target tool restrictions, a declared verification endpoint with
controlled-verification authorization, and a CIDR discovery sweep. Treat it as a
template for your own engagement letters. (`make_client_request_pdf.py` regenerates
it — edit the client, targets and addresses at the top of that script for your own
engagements.)

---

## Testing

The backend has a pytest suite (233 tests) covering the analyzer, planner, policy engine
(including the ZAP baseline's flag surface: the active-scan, config-file, daemon-option
and report-writing flags are all refused), the operator API-key gate, the secret store,
request models, engagement parser, the phase model, the exploit planner, the
recommendation loop (Level 1 auto-drafting and the Level-2 automatic proposal batches
with their budget cap), attack-path derivation and grounded narrative citation, the
next-step proposal engine (state-digest bounds, duplicate suppression, provenance
verification, policy refusals, prompt-injection confinement), the SSH/tmux VM executor,
and the end-to-end API workflow across all phases. The analyzer and planner tests are
written against output the scanners really produced in the Docker stack — escape codes,
tentative nmap matches and all.

```bash
cd backend
# Windows:
venv\Scripts\python.exe -m pytest -q
# macOS/Linux:
python -m pytest -q
```

There is also a live end-to-end smoke run against a running backend — it imports the
letter, registers the targets, and walks the **whole phased flow**: drafts and executes
the recon plan, analyzes (which auto-drafts the exploitation plan from the findings),
executes it, analyzes the verification evidence (which auto-drafts the bounded
post-exploitation plan), executes and analyzes it, and generates the report — then
repeats discovery for the letter's subnet target:

```bash
# with a backend running (Docker stack or native uvicorn); the operator key is required:
set REDTEAM_API_KEY=<your-key>            # or the generated key from the backend console
set SMOKE_BASE_URL=http://localhost:8000  # only if the backend is not on :8000
backend\venv\Scripts\python.exe backend\smoke_e2e.py
```

Without the lab reachable, every command still executes and records its exit code
(the pipeline completes, it just gathers nothing from unreachable hosts) — so the smoke
run passes both against a backend alone and in the full VirtualBox lab.

`pytest.ini` sets `testpaths = test_*.py` so pytest never parses the `[IMPLEMENTATION]`
segment of the project path as parametrization syntax.

### Quantitative evaluation (and the AI ablation)

`backend/eval_harness.py` turns the same phased flow into measurements: N runs per
target, each timed phase-by-phase (planning / execution / analysis / reporting), with
per-run command counts, findings, severity mix, verification outcomes and policy
refusals, summarized as mean/stdev/min/max. With `--checklist <file>` it also computes
recall against a ground-truth list (a Metasploitable2 checklist ships in
`backend/checklists/`). With `--ablate` it runs every arm twice — once with the
provider endpoint cleared (deterministic path) and once restored (AI path) — producing
the PentestGPT-style ablation comparison; the provider's stored key is never touched.

```bash
cd backend
venv\Scripts\python.exe eval_harness.py --targets "Meta2=192.168.56.101" --exploit \
    --checklist checklists/metasploitable2.txt --runs 3 --out eval_results.json
```

---

## Project structure

```
.
├── backend/
│   ├── main.py                     # FastAPI application & endpoints
│   ├── database.py                 # ORM models, migrations, secret migration
│   ├── models.py                   # Pydantic request models
│   ├── modules/
│   │   ├── api_auth.py             # Operator API-key gate (env key or generated digest)
│   │   ├── engagement_parser.py    # Engagement letter → structured brief
│   │   ├── phases.py               # The engagement phase model
│   │   ├── planner.py              # Assessment plan generation
│   │   ├── exploit_planner.py      # Findings → exploitation / post-exploitation steps
│   │   ├── next_steps.py           # Adaptive next-step proposals (ranked, policy-checked)
│   │   ├── attack_paths.py         # Finding graph → attack paths + grounded narratives
│   │   ├── policy_engine.py        # Allowlist command validation
│   │   ├── executor.py             # Sandboxed subprocess execution
│   │   ├── ssh_executor.py         # Kali attacker-VM engine (SSH + tmux)
│   │   ├── analyzer.py             # Findings correlation & scoring (incl. ZAP baseline)
│   │   ├── reporter.py             # HTML report rendering
│   │   ├── secret_store.py         # Credential encryption at rest
│   │   └── templates/
│   │       └── report_template.html
│   ├── test_*.py                   # pytest suite (233 tests)
│   ├── smoke_e2e.py                # live end-to-end phased run
│   ├── eval_harness.py             # quantitative evaluation + AI ablation
│   ├── checklists/                 # ground-truth checklists for recall
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 # state owner & layout; panels in components/
│   │   ├── components/             # one panel per file (plan editor, findings, ...)
│   │   ├── lib/                    # request wrapper, constants, shared context
│   │   ├── App.css
│   │   └── main.jsx
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml              # backend + frontend (the assessor's toolkit)
├── JuiceBox_Security_Assessment_Request.pdf   # sample engagement letter
├── make_client_request_pdf.py      # regenerates the sample letter
└── data/                           # SQLite DB + generated reports (gitignored)
```

---

## API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness check (the one unauthenticated route) |
| `GET` | `/capabilities` | Public list of enabled capabilities and their tools |
| `GET` / `PUT` | `/settings` | Read / update provider & proxy configuration (secrets write-only) |
| `POST` | `/requirements/extract` | Extract plain text from an uploaded requirements document |
| `POST` | `/engagement/parse` | Parse an uploaded engagement letter into a structured brief |
| `POST` / `GET` | `/targets/` | Create / list authorized targets |
| `POST` / `GET` | `/assessments/` | Create / list assessments |
| `GET` | `/assessments/{id}` | Full assessment detail (plan, executions, findings) |
| `PUT` | `/assessments/{id}/plan` | Replace the command plan (before execution begins) |
| `POST` | `/assessments/{id}/execute` | Approve & execute a single plan step |
| `GET` | `/assessments/{id}/executions/{execution_id}/live` | Partial output of an in-flight command |
| `POST` | `/assessments/{id}/analyze` | Correlate executed outputs into findings (auto-drafts the next phase) |
| `POST` | `/assessments/{id}/next-steps` | Propose ranked, policy-checked next steps for the current phase (persists nothing) |
| `GET` | `/assessments/{id}/recommendations` | The automatic proposal batches recorded after each execution |
| `POST` | `/assessments/{id}/phases/{phase}/plan` | Draft a later phase's plan from analyzed findings |
| `GET` | `/assessments/{id}/phases` | Per-phase step and analysis counts (for the stepper) |
| `POST` | `/assessments/{id}/report` | Generate the HTML report (findings, attack paths, audit trail) |
| `GET` | `/reports/{id}` | Download a generated report |
| `DELETE` | `/assessments/{id}` | Delete an assessment with everything derived from it |
| `POST` | `/workspace/reset` | Clear every target, assessment and report |

All routes except `/health` require the `X-API-Key` operator header.

---

*Built for authorized laboratory environments only. Human approval is required before
every command.*
