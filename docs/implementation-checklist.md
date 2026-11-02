# Implementation checklist

Updated November 2, 2026. This checklist records completed review work and the
remaining deployment validation. The
[backend review](backend-review-2026-11-02.md) retains the original reproductions.

## Completed

- [x] Owned-host promotion checks parent scope/exclusions, preserves restrictions and rejects duplicate concurrent requests.
- [x] Encrypted execution/attempt originals, redacted public evidence, audited reveal and retirement of legacy public reports.
- [x] Revision-checked analysis, phase drafting, autopilot and immutable report publication with rollback/concurrency regressions.
- [x] External worker waits for schema head and completion of protected-evidence backfill.
- [x] Durable bounded jobs, cancellation, reconnectable output, immutable attempts and tool-specific outcomes.
- [x] Optimistic plan versions, per-step immutability, phase-aware invalidation and no-op/rationale-only handling.
- [x] Versioned migrations, indexes, campaign deletion order and parent/child deletion guards.
- [x] Structured exclusions, exact/wildcard scopes, test windows and supported execution budgets.
- [x] Trusted SSH identity, key authentication, bounded channels and literal command argument quoting.
- [x] Bounded document extraction, table handling and extraction warnings.
- [x] Shared provider transport, deterministic baseline findings, validated enrichment and failure/usage telemetry.
- [x] Paginated workspace, evidence on demand, remediation reviews and assessment comparison.
- [x] Report provenance and correlation language that does not claim proof of an attack chain.
- [x] Assessment-scoped requests/polling, preserved unsaved edits, operator-key retry and optional persistence.
- [x] Responsive navigation, accessible controls, findings search, campaign panels, terminal and report history.
- [x] Aggressive-lab campaign phases with evidence-derived footholds, encrypted loot, `$$loot:<id>$$` references and explicit approval.
- [x] Opt-in autopilot that drafts/proposes within its budget and never approves or executes.
- [x] Production API/scanner/frontend definitions, readiness/resource controls and CI check definitions.
- [x] Evaluation precision/verification accuracy, ablation restoration and strict smoke evidence requirements.
- [x] Updated README, deployment/API/testing guides and Markdown/PDF references.

## Recorded checks

November 2: **412 backend tests** in the full run, followed by **59 focused
tests** and **one worker-startup regression**; **24 frontend tests**, lint and
production build passed. Focused runs overlap the full suite. Browser checks
used synthetic fixtures at widths from 320 to 1920 pixels.

The earlier October 7 baseline recorded 377 backend and 6 frontend tests.
It is historical, not the current result. See [testing](testing.md) for precise
scope, isolated commands and warnings.

## Deployment follow-ups

- [ ] Build and run the production stack on the deployment host; verify its actual CI run results.
- [ ] Upgrade the operator database with its existing key and backups, then verify readiness and report regeneration.
- [ ] Run strict live smoke checks with authorized reachable targets and installed scanners.
- [ ] Verify SSH identity, VM tools and configured providers in that environment.
- [ ] Add cross-process ownership before sharing one SSH tmux pane among workers.
- [ ] Pin remaining APT/campaign package inputs where reproducible images are required.

These are not implied by mocked regressions or CI configuration. See
[deployment](deployment.md) and [upgrade notes](protected-evidence-upgrade.md).
