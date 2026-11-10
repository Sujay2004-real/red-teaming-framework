# Testing and validation

Use isolated test data. Automated tests mock scanner/provider behavior unless a
test explicitly says otherwise; they do not establish security coverage for a
real target.

## Backend

Install the development requirements, then run from the repository root:

```sh
python -m pip install -r backend/requirements-dev.txt
python -m pytest backend -q -p no:cacheprovider
```

Tests use temporary databases, encryption keys and authenticated clients.
Important suites cover policy refusal paths, scope inheritance, durable jobs,
cancellation, migrations, evidence protection, report publication, scenarios,
campaign controls, objectives, credentials and worker leases.

To avoid writing test state into the application database, set an isolated
database and secret key when running custom scripts or interactive checks.

## Frontend

Run from `frontend/` with Node.js 22:

```sh
npm ci
npm test
npm run lint
npm run build
```

Vitest and Testing Library cover UI and request behavior with mocked backend
responses. A passing frontend suite is not proof of backend reachability or
scanner compatibility.

## Compose and images

From the repository root:

```sh
REDTEAM_API_KEY=validation-key docker compose -f docker-compose.yml config
REDTEAM_API_KEY=validation-key docker compose -f docker-compose.prod.yml config
docker build --target api -t redteam-api:check ./backend
docker build --target scanner -t redteam-scanner:check ./backend
docker build -f frontend/Dockerfile.prod -t redteam-frontend:check ./frontend
```

In PowerShell, set `$env:REDTEAM_API_KEY = 'validation-key'` before the Compose
commands. Building the scanner image requires network access to its pinned tool
sources.

## Authorized deployment checks

Before production use, verify the actual environment separately:

- database backup/restore and preservation of `REDTEAM_SECRET_KEY`;
- API and worker readiness at migration `0006_framework`;
- browser origin, reverse proxy and operator authentication;
- worker access to only the authorized target networks;
- installed scanner versions and SSH host-key verification;
- cancellation, report download and cleanup/retest workflows.

Record the release tag, commit SHA, environment and exact authorization scope
with deployment evidence. Never treat unit-test counts as target findings.
