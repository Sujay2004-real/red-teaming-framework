# Visual demo polish

This document preserves the dated UI review record. For current setup and
validation, see the [frontend guide](../frontend/README.md) and
[testing guide](testing.md).

The workspace keeps its dark navy and teal style, with clearer hierarchy,
larger controls, consistent SVG icons, and restrained motion.

## What changed

- Letter import is the main entry point. Manual setup expands when needed.
- A selected assessment shows its target, phase, status, and recorded command
  progress before the workflow and scope details.
- The workflow distinguishes completed, current, upcoming, and unauthorized
  phases and offers one next action based on saved state.
- Command cards show purpose and approval first. Editing and recorded evidence
  expand on demand; active execution output stays visible.
- Findings show severity totals and distribution across the complete filtered
  result, with quick severity filtering and an explicit reset.
- Operator-key errors allow retry, selected requirements files remain visible,
  and workspace totals cover all pages.
- Report generation provides an explicit open link and a separate download,
  avoiding dependence on automatic popups.
- Desktop, tablet, and narrow layouts share the same palette and controls;
  reduced-motion preferences disable animation.

## Verification

Run `npm run build`, `npm run lint`, and `npm test` in `frontend`.
The checks passed with 13 frontend tests and 45 backend workflow tests.
The UI regression tests cover key retries, stale unauthorized responses,
assessment hierarchy, attachments, recorded output, retries, and report links.
Async UI tests have a 15-second timeout to accommodate the local Windows
environment; assertions still determine whether they pass.
The initial pass could not capture browser screenshots. The follow-up review
below completed browser verification using the installed Edge browser.

Backend coverage is in `test_workflow_reliability.py` and
`test_api_workflow.py`, including totals across pages and filtered severity
aggregation. Use the existing `backend/venv` environment for these tests.

## Before the live demo

Restart the backend to load the new response fields, then refresh the frontend.
Rehearse on the actual presentation screen through import, plan review,
approval, execution, findings, evidence review, and report opening.
Verify the configured provider and execution engine on the demo machine.
Check the engagement dates in the letter and enforced policy against the
actual demo date; the older Demo.txt guidance contains a September test window.

Automated tests do not establish that every external provider, VM, target,
or projector setup will work in the live environment.

## UI review — November 2, 2026

- Workspace and assessment navigation stay visible while scrolling. A compact
  mobile switcher exposes the assessment list above the active workspace;
  selecting an assessment closes it and moves focus to the selected content.
- Assessment search filters the current catalog page by target, objective,
  ID, or status. The list scrolls independently when it contains many runs.
- The next action appears before the phase diagram. Reconnaissance captions
  show recorded counts and no longer imply execution before any command runs.
- Findings search waits 300 ms after typing and retains the previous results
  while fetching, with explicit updating, empty, error, reset, and retry states.
  Pagination is hidden when there is only one page.
- Registered targets appear in their own inventory, with expandable scope
  rules. Settings group provider, proxy, and execution fields. Form helper
  text and entered values use a consistent, readable weight.
- Campaign tables scroll within keyboard-focusable containers instead of
  widening the page. Focus indicators, a skip link, notification placement,
  severity badges, and workflow connectors were also refined.

Validation: the frontend's 15 tests, production build, lint, and diff whitespace
check passed. A headless Edge review captured 22 views and checked widths of
320, 390, 768, 1024, 1440, and 1920 px, with reduced motion enabled. Checks
covered navigation overlap, page overflow, keyboard entry and focus, mobile
assessment switching, search reset, evidence expansion, the VM settings form,
empty workspace, and operator-key gate. No page errors or failed browser
assertions were recorded.

Browser API responses were intercepted with synthetic fixture data; these
checks did not run scanners, contact targets, or test a live provider/backend.
The local review script and before/after screenshots are in
`.runlogs/ui-review/` (ignored by Git). Run `node .runlogs/ui-review/review.cjs final`
with the frontend dev server at `http://127.0.0.1:5173` to repeat the local check.
The script uses this machine's bundled Playwright and installed Edge browser.

## UI reliability follow-up — November 2, 2026

- Background assessment refreshes preserve unsaved command edits. Saving adopts
  the server-confirmed plan, and a failed assessment switch leaves the current
  assessment usable and refreshable.
- Creating an assessment resets the active tab, proposals, and report link;
  unsaved edits require an explicit discard before creation starts.
- Configuration edits survive catalog and connection refreshes. The workspace
  engine label reflects saved settings. Connection tests validate the form,
  clear submitted secret fields after saving, and invalidate outdated results.
  Fingerprints from a different SSH destination cannot be trusted from the UI.
- Prohibited tools accept comma-separated typing, with normalization on blur.
  SSH ports can be cleared and replaced, and search/objective limits match
  the backend limits.
- The next action offers reporting when verification is unauthorized and
  command review when the current phase already has a plan.
- Regenerating a report refreshes its history even when status stays reported.
  Downloads and review saves show their busy state, and duplicate shared
  actions are ignored while a request is active.
- Campaign failures appear in the panel, with retry for initial loading errors.
  Long fingerprints and report hashes wrap within their containers.

Nine regression tests are in `frontend/src/components/UiReliability.test.jsx`.
The expanded browser script is `.runlogs/ui-review/audit.cjs`; its 25 captured
views are in `.runlogs/ui-review/audit-after/`. Browser checks passed at widths
from 320 through 1920 pixels with no page errors or page overflow. All browser
API responses used synthetic fixtures; no live scanners or SSH connections
were exercised. Production build, lint, and frontend whitespace checks passed.
All 24 frontend tests passed with `npm test -- --maxWorkers=1`. A concurrent
run hit the existing 15-second timeout in one workflow test; the serial run
passed without changing timeouts or assertions.

## Protected-evidence integration - November 2, 2026

Recorded and live execution output uses redacted evidence. Original access is
an explicit audited API operation; ordinary report downloads remain redacted.
The report panel identifies retired pre-upgrade versions, explains why their
public downloads are unavailable and directs the operator to regenerate.
An unchanged plan save preserves the current report; reason-only edits require
regeneration. Later unexecuted command edits preserve earlier phase findings.

See [upgrade notes](protected-evidence-upgrade.md) for original access and legacy
report handling. The 24-test frontend result above includes the final UI checks;
this documentation update does not assert another live browser run.
