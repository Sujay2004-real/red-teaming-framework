# Remaining review implementation

The review recommendations have been implemented. This checklist records the completed scope and the validation status.

The additional changes from the [November 2 backend review](backend-review-2026-11-02.md)
were approved and implemented. See the [upgrade notes](protected-evidence-upgrade.md)
for migration, retired legacy reports and audited raw-evidence access.

- [x] Parent-scope/exclusion enforcement, owned-host checks and atomic child promotion.
- [x] Encrypted execution/attempt originals, redacted public evidence, audited reveal and legacy report retirement.
- [x] Revision-checked analysis, phase transitions, autopilot and immutable report publication, with rollback/concurrency regression tests.

- [x] Durable bounded execution jobs, cancellation, reconnectable incremental output, immutable attempt history and tool-specific outcomes.
- [x] Optimistic plan concurrency, lifecycle gates, dependency invalidation and versioned database migrations/indexes.
- [x] Structured scope exclusions, exact/wildcard scope semantics, test windows and execution budgets.
- [x] Pinned SSH identity, key authentication, bounded channels and isolated per-command proxy environment.
- [x] Bounded document extraction with tables and extraction warnings.
- [x] Shared provider transport, deterministic baseline findings, validated AI enrichment and failure/usage telemetry.
- [x] Paginated summaries, on-demand evidence, remediation workflow and assessment comparison.
- [x] Versioned atomic reports, provenance and accurate correlation language.
- [x] Reliable assessment/request hooks, scoped recommendation polling and optional operator-key persistence/lock.
- [x] Navigation, overview/plan/findings/activity/report views, onboarding, accessible controls, terminal and findings improvements.
- [x] Production frontend/backend deployment, pinned dependencies, readiness/resource limits and CI validation.
- [x] Evaluation precision/verification accuracy, safe ablation restoration and strict smoke evidence checks.
- [x] Backend/frontend regression suites, UI verification and documentation.
- [x] Full red-team kill chain for lab targets: aggressive-lab-gated credential validation, lateral movement and impact; evidence-derived footholds/loot/hosts with secrets encrypted at rest and masked as `$loot:<id>$` placeholders; audited reveal; child-assessment promotion; opt-in autopilot that drafts and proposes but never approves or executes; campaign UI surface.


Validation (2026-10-07): backend `377 passed` with one existing Starlette/httpx deprecation warning; frontend `6 passed`, production build clean. The campaign suite drives the real API (executor mocked) through the aggressive-lab gate, evidence ingestion, placeholder-masked execution, audited loot reveal, host promotion, autopilot and a full credential-validation → lateral-movement → impact walk. Both compose files validate with `docker compose config`; the production images build under the `docker-images` CI job. Docker itself was unavailable on the development laptop, so the images were not built or run locally — CI is the standing build proof.
