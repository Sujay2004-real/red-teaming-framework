# Testing and validation

## Recorded implementation checks

The November 2, 2026 review used isolated databases, synthetic credentials and
mocked scanners/provider behavior. The active operator database was not migrated.

| Run | Result | Scope |
| --- | --- | --- |
| Complete backend suite after major fixes | 412 passed | Backend API, policy, evidence, migrations and workflows |
| Later focused backend run | 59 passed | Final scope, phase and evidence regressions |
| External-worker startup regression | 1 passed | Worker waits for evidence backfill |
| Frontend suite | 24 passed | Component/request behavior with mocked API responses |
| Frontend lint and build | Passed | ESLint and Vite production compilation |
| Browser review | 25 mocked views passed | Prior UI review; not live scanner evidence |

The backend runs overlap; do not add their counts. The full-suite count predates
the last two focused additions. Historical 378/386-test results in the review
describe earlier checkpoints, not the current total. Two local backend warnings
were the Starlette/httpx deprecation and an unwritable pytest cache.

Docker images, live VM/scanner compatibility, provider connectivity and the real
operator database were not exercised in that review. These require separate
deployment validation.

## Documentation refresh checks

The November 2 documentation refresh checked all 45 unique application
method/path pairs against the API source and resolved 87 local links across
15 Markdown guides. All three reference PDFs were regenerated from Markdown;
their 15 pages passed text/bounds checks and visual review. Git whitespace
checks cover text files; PDFs are marked binary to preserve their exact bytes
across platforms. This documentation pass did not rerun live scanners or the
application test suites.

## Backend tests

Use a virtual environment and install `backend/requirements-dev.txt`.
From `backend/`, this wrapper gives the global database an in-memory URL, uses
an ephemeral encryption key, and creates a fresh temp directory for the run:

```sh
python -c "import os,runpy,sys,uuid; from cryptography.fernet import Fernet; os.environ['DATABASE_URL']='sqlite://'; os.environ['REDTEAM_SECRET_KEY']=Fernet.generate_key().decode(); sys.argv += ['--basetemp=.pytest_tmp_'+uuid.uuid4().hex]; runpy.run_module('pytest',run_name='__main__')" -q -p no:cacheprovider
```

On Windows, substitute `.\venv\Scripts\python.exe` for `python` if the
environment is not activated. Use `Set-Location -LiteralPath` for directory
names containing brackets. `-p no:cacheprovider` avoids cache-directory ACL
problems without disabling assertions. Fixtures supply temporary databases,
foreign-key enforcement and authenticated TestClients.

To inspect the current collected test count, use `--collect-only -q` with the
same isolated wrapper. Collection is not a test execution.

Important suites include:

- `test_protected_workflows.py`: scope inheritance, concurrent promotion/drafts,
  rollback, stale publication, encrypted retry originals, redaction, wrong keys,
  atomic key creation, backfill and worker startup gating.
- `test_backend_review.py`: later-phase edits, no-op/rationale saves, controlled
  recon-redraft conflicts, malformed auth and campaign deletion/reset.
- `test_workflow_reliability.py`: durable jobs, cancellation, leases, attempts,
  scopes, migrations, reviews and versioned reports.
- `test_campaign_api.py`, `test_footholds.py`: campaign parsing, planning,
  credential references, promotion and autopilot.
- Policy, verification, planner, analyzer, next-step, SSH and engagement suites
  cover refusal paths as well as successful workflows.

## Frontend tests

From `frontend/`:

```sh
npm ci
npm test -- --maxWorkers=1
npm run lint
npm run build
```

Vitest and Testing Library exercise UI/request behavior. The single-worker flag
is useful on constrained Windows machines; CI currently uses `npm test`.
A mocked view is not proof of backend reachability or scanner compatibility.

## Live smoke testing

`backend/smoke_e2e.py` runs actual approved scanner steps against a running API
and the sample letter's targets. Inspect and adapt that letter to the authorized
lab before invoking the script. Set `REDTEAM_API_KEY` and, if needed,
`SMOKE_BASE_URL`.

The smoke script defaults to strict evidence checks. A strict pass requires
successful scanner outcomes and observed lab evidence. Workflow-only mode
relaxes those checks and must never be reported as target coverage.
Consult the script's `SMOKE_STRICT` handling for the exact mode switch.

Unlike unit tests, this script writes assessments and evidence to the running
service and can make network connections through the configured executor.
Run it against a dedicated authorized test workspace.

## Evaluation

`backend/eval_harness.py` measures phase timings, counts, outcomes and
ground-truth metrics. It needs a running authorized lab; no benchmark improvement
or time saving is established by unit-test counts.

The `--checklist` option supports partial exact-title checklists and structured
ground truth. Partial checklists support recall but cannot establish precision.
Use complete labeled truth for precision and labeled verification truth for
verification accuracy. See [formula definitions](backend_algorithms_formulae_reference.md).

`--ablate` compares deterministic and configured-provider arms and restores
provider endpoint/model settings afterward. Run in a dedicated evaluation
workspace because the harness changes service state.

## CI

[The workflow](../.github/workflows/ci.yml) runs on pushes to `main`/`master`
and pull requests. It configures:

- Python 3.12 backend tests.
- Node 22 dependency install, lint, tests, high-severity npm audit and build.
- Development/production Compose validation and API/scanner/frontend image builds.

It does not run the live smoke test. Check the corresponding
[Actions run](https://github.com/Sujay2004-real/red-teaming-framework/actions)
before claiming that CI or image builds passed for a commit.
