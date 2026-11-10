# API reference

The API version is 4.0.0. Paths below are relative to the backend base URL
(`http://localhost:8000` for development, `http://localhost:8080/api` behind
production Nginx).

The [framework API reference](framework.md#api-reference) documents scenario
versions, previews, controls, cleanup, telemetry, retests, workers and team
credentials added in 4.0. The assessment routes below remain available.

## Authentication and transport

Application routes require `X-API-Key: <operator-key>`, except **GET /health**
and **GET /ready**, which are unauthenticated probes. FastAPI's default
`/docs`, `/redoc` and `/openapi.json` are schema/documentation endpoints and
also do not carry the operator dependency. `/capabilities` is protected.

Named credentials use this same header. Viewer credentials are read-only;
operators cannot administer keys, change settings, reset the workspace or
reveal originals. The bootstrap key remains an administrator. Roles share one
workspace rather than separate tenant data.

Use JSON for structured requests and multipart form data with field `file`
for uploads. Uploads are bounded to 5 MiB. For the exact request schemas and
bounds, see [models.py](../backend/models.py) and
[workspace_api.py](../backend/modules/workspace_api.py), or the running API's
OpenAPI documentation. Never put the operator key in a query string.

## Service, settings and setup

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Process liveness |
| GET | `/ready` | Schema readiness and configured external-worker heartbeat; 503 if unavailable |
| GET | `/capabilities` | Supported capabilities, tools and policy metadata |
| GET | `/settings` | Configuration with secret-presence booleans |
| PUT | `/settings` | Save provider, proxy and execution/SSH configuration |
| POST | `/settings/ssh-fingerprint` | Inspect the presented SSH host-key fingerprint |
| POST | `/settings/ssh-test` | Test trusted SSH configuration and return tool/host information |
| POST | `/requirements/extract` | Extract text from an uploaded document |
| POST | `/engagement/parse` | Parse an uploaded engagement brief |
| POST | `/targets/` | Register a target with authorized scope and policy |
| GET | `/targets/` | List targets |

Inspecting a fingerprint does not substitute for verifying and trusting it.
Provider use requires a key, HTTP(S) base URL and model. Empty secret-setting
fields retain stored values.

## Assessments, plans and phases

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/assessments/` | Create an assessment with a supplied or drafted plan |
| GET | `/assessments/` | List assessments |
| GET | `/assessments/{assessment_id}` | Assessment, plan, executions and findings |
| GET | `/catalog/assessments` | Paginated assessment catalog |
| GET | `/assessments/{assessment_id}/snapshot` | Bounded UI summary |
| DELETE | `/assessments/{assessment_id}` | Delete assessment and dependent rows; refuses live work or undeleted children |
| GET | `/assessments/{assessment_id}/discovered-hosts` | Nmap host inventory |
| PUT | `/assessments/{assessment_id}/plan` | Save editable plan fields with optimistic version checking |
| GET | `/assessments/{assessment_id}/phases` | Phase progress and analysis counts |
| POST | `/assessments/{assessment_id}/phases/{phase}/plan` | Draft eligible later-phase work |
| POST | `/assessments/{assessment_id}/next-steps` | Compute advisory proposals without persisting a batch |
| GET | `/assessments/{assessment_id}/recommendations` | Persisted batches/tasks and audit records |

An executed step's position, tool, command, phase and enabled state cannot change.
Idle unexecuted steps remain editable. A save may increment `plan_version`
even when the plan is unchanged. An unchanged save preserves analysis/report;
rationale-only edits invalidate the current report; execution-bearing edits
invalidate the earliest changed phase and its dependents.

A reconnaissance redraft returns 409: recon is drafted during creation.
An already-drafted phase cannot be appended again through the draft route.
Drafting does not grant execution approval.

Example plan save:

```json
{
  "plan_version": 1,
  "plan": [
    {
      "tool": "curl",
      "command": "curl -I http://lab.test",
      "phase": "recon",
      "enabled": true,
      "reason": "Inspect the authorized service headers."
    }
  ]
}
```

## Executions and analysis

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/assessments/{assessment_id}/execute` | Approve one enabled step in the active phase |
| GET | `/assessments/{assessment_id}/executions/{execution_id}/live` | Redacted incremental output with cursor/reset metadata |
| POST | `/assessments/{assessment_id}/executions/{execution_id}/cancel` | Request cancellation or cancel a queued job |
| GET | `/assessments/{assessment_id}/executions/{execution_id}/attempts` | Redacted archived attempt snapshots |
| GET | `/assessments/{assessment_id}/executions/{execution_id}/evidence` | Ordinary redacted execution detail |
| POST | `/assessments/{assessment_id}/executions/{execution_id}/evidence/reveal` | Audited original evidence; optional `?attempt=N` |
| POST | `/assessments/{assessment_id}/analyze` | Atomic current-phase analysis, verification, ingestion and eligible auto-draft |

Background approval example:

```json
{
  "step_index": 0,
  "approved": true,
  "background": true,
  "plan_version": 1
}
```

Background requests and external-worker mode return **202** with an execution ID.
Poll the live route using `cursor=0`, then the last returned cursor. Respect
`reset` because the retained public buffer is bounded. Complete redacted lines
appear while running; unfinished lines are withheld. The finished transcript
contains the executor's bounded output.

The embedded-mode compatibility path can wait for execution and return 200.
A lost HTTP connection does not cancel a durable background job. Successful
steps cannot simply be run again; failed/interrupted attempts require explicit
re-approval. Analysis requires every enabled current-phase step to have a
terminal result and returns the failed step indices alongside findings.

## Campaign and review

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/assessments/{assessment_id}/campaign` | Footholds, masked loot, hosts and autopilot state |
| POST | `/assessments/{assessment_id}/autopilot` | Enable/disable with `{"enabled": true/false}` |
| POST | `/assessments/{assessment_id}/autopilot/run` | One bounded draft/proposal iteration; never execute |
| GET | `/assessments/{assessment_id}/loot/{loot_id}/reveal` | Audited decryption of one recovered credential |
| POST | `/assessments/{assessment_id}/promote/{host_id}` | Create one owned, in-scope child assessment; optional objective |
| GET | `/assessments/{assessment_id}/findings` | Paginated/filterable findings and filtered severity counts |
| GET | `/assessments/{assessment_id}/findings/{finding_id}` | Finding detail and review |
| PUT | `/assessments/{assessment_id}/findings/{finding_id}/review` | Owner, due date, status, comments and retest evidence |
| GET | `/assessments/{assessment_id}/compare/{baseline_id}` | Compare analyzed assessments of the same target and phase coverage |

Autopilot and promotion require aggressive lab mode with exploitation permission.
Promotion also requires owned state, host-wide parent authorization and no
excluded-scope overlap. URL/path/port-only permissions are insufficient.
Concurrent duplicate promotions return 409.

Finding review statuses are `open`, `in_progress`, `resolved`,
`accepted_risk` and `reopened`. Accepted risk requires justification;
resolution requires retest evidence. A finding absent in another run is
"not observed," not automatically remediated.

## Reports and workspace

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/assessments/{assessment_id}/report` | Stage and publish a report after revision validation |
| GET | `/reports/{assessment_id}` | Current committed public report; 404 if unavailable |
| GET | `/assessments/{assessment_id}/reports` | Versions, digests, provenance and `restricted` flags |
| GET | `/assessments/{assessment_id}/reports/{version_id}` | Historical public version; 409 for restricted legacy originals |
| POST | `/assessments/{assessment_id}/reports/{version_id}/reveal` | Audited legacy-original attachment |
| POST | `/workspace/reset` | Clear targets/assessments/evidence/reports; retains settings and refuses live work |

Report creation returns `version_id`, `digest` and `download_url`. It
requires an analyzed/reported assessment. Slow rendering that loses a revision
race returns 409 and cannot replace the current report.

Original reveals commit an `evidence_access` audit record before returning
data and set `Cache-Control: no-store`. The legacy report reveal is an
attachment rather than inline HTML. Missing/wrong encryption keys return 409.
See [evidence access and migration](protected-evidence-upgrade.md).

## Common responses

| Status | Meaning |
| --- | --- |
| 200 / 202 | Completed request / accepted durable job |
| 400 / 422 | Invalid request, input bound or no usable draft |
| 401 | Missing or invalid operator key |
| 403 | Policy, scope or authorization refusal |
| 404 | Missing resource or no current report |
| 409 | Stale revision, active work, unmet phase prerequisite, immutable step, restricted report or unreadable original |
| 429 | Execution queue capacity reached |
| 503 | Service/readiness/configuration temporarily unavailable |

Reload and review state after a conflict. Do not automatically re-approve a
scanner command just because a request failed.
