# Implementation results

Updated November 2, 2026. This document supplies implementation facts for the
final project report. Historical results are labeled with their original date;
test counts are not measurements of live scanner coverage or detection accuracy.

## Architecture and implementation

| Area | Main source | Implemented responsibility |
| --- | --- | --- |
| API and workspace | `main.py`, `modules/workspace_api.py` | Authenticated workflows, paginated catalog, evidence, reviews and comparison |
| Persistence | `database.py`, `migrations/` | 13 tables, Alembic migrations, foreign keys and workflow revisions |
| Execution | `modules/jobs.py`, `worker.py`, executors | Durable bounded jobs, leased claims, cancellation, attempt archives and local/SSH execution |
| Policy | `policy_engine.py`, `scope_rules.py`, `command_values.py` | Tool/argument allowlists, scope/exclusions, engagement windows and lab gates |
| Planning | `planner.py`, `exploit_planner.py`, `planners.py` | Reconnaissance, verification and evidence-derived campaign steps |
| Evidence | `evidence.py`, `secret_store.py`, `footholds.py` | Encrypted originals, redacted public text, recovered credentials and host inventory |
| Analysis | `analyzer.py`, `verification.py`, `attack_paths.py` | Deterministic parsers, optional provider enrichment, scoring and grounded correlations |
| Suggestions | `next_steps.py`, `auto_recommend.py` | Bounded policy-checked proposals and opt-in drafting |
| Reports | `reporter.py`, `report_versions.py`, `workflow.py` | Staged rendering, immutable versions, provenance and revision-checked publication |
| Frontend | `frontend/src/App.jsx`, components and hooks | Responsive workspace, plan editing, findings, campaigns, settings and reports |

Source paths in this table are relative to `backend/` unless prefixed with
`frontend/`. See the [technical reference](backend_technical_reference.md) and
[API reference](api-reference.md) for the current details.

## Authorized assessment lifecycle

The normal flow is scoping, recon, vulnerability analysis, exploitation,
post-exploitation and reporting. Aggressive lab mode adds credential validation,
lateral movement and impact before reporting. These phases represent implemented
workflow support; they do not claim that every target or exploit is supported.

- Campaign operations require both `exploitation_authorized` and `aggressive_lab`.
  Ordinary target restrictions continue to apply at drafting and execution.
- Evidence ingestion creates only records recognized in observed output.
  Discovery alone does not establish ownership or permit promotion.
- Planners use `$$loot:<id>$$` references. Secrets are resolved immediately before
  execution; encrypted originals preserve the executed command and output.
  Ordinary evidence, provider inputs and reports use redacted projections.
- Executable operator-authored plans are not a general secret vault. Redaction
  recognizes supported secret formats and known recovered values; arbitrary
  unlabelled strings may not be recognized.
- Every command requires explicit operator approval and revalidation.
  Autopilot can draft and propose, but cannot approve or execute.
- Promoting an owned host requires parent host-wide permission, honors exclusions
  and copies restrictions. URL/path/port-only scope cannot become a whole-host
  child assessment. Concurrent duplicate promotion is rejected.

## Workflow correctness

Executed steps keep their execution-bearing fields and position. Later
unexecuted edits invalidate only the earliest changed phase and its dependents.
An unchanged save preserves analysis and the current report; a rationale-only
edit preserves analysis but requires a fresh report.

Analysis publishes findings, verification, campaign ingestion, phase state and
eligible automatic drafting in one transaction. Competing changes are rejected
using the assessment revision. Report rendering stages a unique file and
publishes an immutable version only if the captured revision remains current.

Automatic recommendation batches are bounded and tied to the triggering
execution/attempt. Opt-in autopilot has a 25-iteration bound and stops when no
progress is possible. Its local transition commits atomically; subsequent
advisory provider output is saved only against the same committed state.

## Evidence, authorization and governance

| Control | Implemented behavior and limit |
| --- | --- |
| Authentication | Application routes require `X-API-Key`; `/health`, `/ready` and FastAPI schema/docs are public |
| Policy | Explicit tool/flag/value rules; supported destinations and exclusions checked again at execution |
| Scope | CIDR subnet containment, exact names or explicit wildcards, URL restrictions where applicable; promotion requires host-wide authority |
| Exploitation | Letter permission, phase prerequisites and explicit per-step approval |
| Scanner safety | Passive ZAP baseline; dangerous file/script/redirect options refused; no general egress firewall |
| Evidence | Encrypted originals and attempts, redacted public projections, SHA-256 provenance |
| Original access | Authenticated reveal, durable `evidence_access` audit record, `Cache-Control: no-store` |
| Verification | Independent successful sqlmap proof with matching endpoint/parameter; banners and provider claims do not prove exploitation |
| Reports | Immutable versions; pre-upgrade originals are restricted and require audited reveal |
| Deployment | Shared API/worker storage and encryption key; schema/evidence backfill before jobs start |

See [priority fixes](priority_security_fixes.md) and
[upgrade notes](protected-evidence-upgrade.md).

## Recorded verification: November 2, 2026

The full backend suite passed **412 tests** after the approved changes.
A later **59-test focused run** and **one worker-startup regression** also passed.
These runs overlap; do not add their counts into a claimed full-suite total.
The frontend passed **24 tests**, lint and the production build.

Browser review used intercepted synthetic responses at widths from 320 to
1920 pixels. Backend regressions used isolated SQLite databases, mocked
executors and injected failures/interleavings. They covered scope refusals,
concurrent publication, rollback, original encryption, stream redaction, legacy
backfill and UI request isolation.

The [testing guide](testing.md) records commands, warnings and limits. CI defines
tests, dependency audit, Compose validation and image builds. Workflow
configuration alone is not evidence that a particular GitHub run succeeded.

## Evaluation methodology for the final report

`backend/eval_harness.py` measures phase durations, planned/executed commands,
failures, findings, severity mix, policy refusals and ground-truth metrics.
Its ablation compares deterministic analysis with the configured provider and
restores provider configuration afterward.

For an authorized lab, use a reviewed target list and ground truth, repeat each
arm, and retain the emitted JSON with tool versions, environment and engagement
rules. The [testing guide](testing.md) describes harness use. Run
`python eval_harness.py --help` from `backend/` for the supported arguments.

A title checklist supports recall only. Structured, explicitly complete ground
truth also supports precision; verification accuracy uses matched entries with
boolean expected verification. See the
[formula reference](backend_algorithms_formulae_reference.md). Report mean,
spread and failure counts from actual runs. No detection accuracy, speedup or
successful live campaign is inferred from unit tests.

## Historical record: October 7, 2026

The earlier implementation recorded **377 backend tests**, **6 frontend tests**
and a clean frontend build. Its campaign suite drove the API with the executor
mocked through lab gates, evidence ingestion, credential references, audited
reveal, promotion, autopilot and the campaign phase walk.

A Windows workflow smoke run without a lab recorded letter import, an eight-step
recon plan, analysis, two-step exploitation and post-exploitation drafts, report
generation and seven recommendation batches. Authentication returned 401 without
the key and 200 with it. This is historical workflow evidence, not a current
strict scanner-success result.

That pass also fixed campaign-phase invalidation that had erased prerequisite
analysis. The November review extended invalidation and evidence protection;
older statements that credentials never appeared in output are superseded.

## Report framing

Describe the framework as human-approved execution with automatic suggestions.
Use passive ZAP as implemented; active scanning is not part of that adapter.
Describe attack paths as correlations, not proven compromise chains. Keep
measured results separate from proposed evaluation and verify literature
citations independently before submission.
