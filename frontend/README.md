# Red Team Control Center frontend

React 19 and Vite 8 implement the operator interface. See the
[project README](../README.md) and [deployment guide](../docs/deployment.md).

## Run and verify

Use Node.js 22 and run from this directory:

```sh
npm ci
npm run dev
npm test -- --maxWorkers=1
npm run lint
npm run build
```

Vite serves port 5173. `VITE_API_URL` selects the browser API base, defaulting to
`http://localhost:8000`. Production uses `/api` behind Nginx. For separate
origins, configure API `CORS_ALLOW_ORIGINS`. Neither setting replaces the
operator key.

The November 2 review recorded 24 passing UI tests, lint and production build.
Tests mock backend responses and do not execute scanners.

## Source map

| Area | Files |
| --- | --- |
| State and navigation | `src/App.jsx`, `src/lib/AppContext.jsx` |
| Authentication and requests | `ApiKeyGate.jsx`, `src/lib/api.js` |
| Requests and polling | `useResource.js`, `useAssessment.js`, `useExecution.js`, `useRecommendations.js` |
| Assessment setup | `LetterPanel.jsx`, `NewAssessmentPanel.jsx`, `AssessmentsPanel.jsx`, `TargetPanel.jsx` |
| Plan and phase controls | `PlanEditor.jsx`, `CommandCard.jsx`, `PhasePipeline.jsx`, `ScopePolicy.jsx` |
| Analysis and evidence | `AnalysisPanel.jsx`, `FindingsPanel.jsx`, `CampaignPanel.jsx`, `AuditTrailPanel.jsx` |
| Settings and reports | `ConfigurationPanel.jsx`, `ReportVersions.jsx`, `CrewPanel.jsx` |
| Presentation | `src/App.css`, `src/interface.css`, `src/components/Icon.jsx` |

Component names are under `src/components/`; hooks are under `src/lib/`.

## Operator behavior

- The operator key stays in memory unless the user chooses to remember it.
  Requests attach `X-API-Key`. An obsolete request's 401 must not invalidate a
  subsequently replaced key.
- Unsaved plans and executed-step locks are visible. Executed work keeps its
  tool, command, position, phase and enabled state. Other steps remain editable
  while idle. Plan saves and approvals use the plan version.
- Approvals create durable background jobs. Reloading or losing the browser
  connection does not cancel them. Polling reconnects using execution IDs and
  cursors; explicit cancellation is separate.
- Live output and execution details are redacted. Raw evidence requires the
  authenticated, audited reveal API in the
  [upgrade guide](../docs/protected-evidence-upgrade.md).
- Campaign features are for aggressive-lab targets. Autopilot drafts and
  proposes, never approves or executes. Promotion may be refused by backend
  ownership, scope or exclusion checks.
- Findings use paginated reads, filters and review state. Empty, loading and
  error states distinguish no findings from an unfinished or failed request.
- Downloads fetch protected resources with the key and use object URLs.
  Report history disables ordinary downloads of restricted legacy versions
  and directs the operator to regenerate a redacted report.

## Reliability conventions

Abort stale requests and bind results to the assessment that started them.
Keep keyboard interaction, focus/labels, disabled states and responsive layouts
consistent. Do not silently treat network failures as empty data.

Display constants reflect backend phase ordering but do not authorize actions.
The API remains authoritative for scope, prerequisites, approval, conflicts and
report availability. A 409 requires reloading and reviewing the latest state.

See [UI review history](../docs/visual-demo-polish.md) and
[testing documentation](../docs/testing.md).
