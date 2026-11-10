# Framework operation and extension

The 4.0 framework adds reusable scenario campaigns to the existing assessment
workflow. The React application, FastAPI API, local/SSH executors, evidence
store and report publisher use the same execution and policy pipeline.

## What is available

- Versioned technique adapters with typed inputs, ATT&CK references, fixed
  argument construction, and cleanup instructions.
- Built-in web baseline, SQL injection with bounded impact, and TCP service
  inventory scenarios. Workspace scenarios can be imported, exported and
  published as immutable versions.
- Dependency branches for successful, failed, completed, and independently
  verified prerequisites. Verified branches require an earlier analyzed phase.
- Persistent pause/resume/stop controls, cancellation, attempt history,
  revision conflicts and explicit per-command approval.
- SQL injection, database banner, HTTP response, and TCP service objective
  adapters. An HTTP response objective means that a response was observed;
  it does not establish a vulnerability or authentication bypass.
- Detection evidence imported from security tools and matched to an exact
  execution attempt. Missing telemetry is shown as not evaluated.
- Cleanup review tied to each execution attempt, explicit campaign completion,
  fresh retest campaigns and controlled comparisons.
- Named viewer, operator and administrator credentials, approval attribution,
  worker heartbeats and database leases for shared SSH execution sessions.
- Scenario outcomes, dependency decisions, telemetry and cleanup records in
  versioned HTML reports.

The technique library is an extension interface, not a claim of comprehensive
ATT&CK coverage. The included adapters cover web and network work. Identity,
cloud and other domain packs require their own reviewed adapters and evidence
tests. SIEM/EDR support currently accepts exported events through the API; it
does not include vendor credentials, live connectors or automatic log searches.

## Start and upgrade

Use the existing [deployment guide](deployment.md). API startup applies
`0006_framework` after the protected-evidence migration. The migration adds
scenario/state fields, scenario versions, framework events, named credentials,
worker registrations and execution leases. Existing assessments retain their
normal workflow; their scenario field is empty.

Back up the database and preserve its encryption key before upgrading a live
installation. Upgrade API and workers together. External workers wait for the
current migration head. Do not copy the local validation service's test key or
database into an operator deployment.

`GET /ready` should return `schema: 0006_framework`. Workers appear in
**Settings → Execution workers** after their polling loop starts. A local
worker advertises binaries on its own PATH; the Kali connection test checks
the separately configured VM. A scenario preview discloses missing local
tools or an unavailable worker. Creating a plan does not install scanners.

SQLite and the shared database queue support the documented native/container
deployment. Multiple worker processes can cooperate on that deployment; the
lease prevents concurrent use of the same SSH host/port/account. This is not
a geographically distributed runner service, and the application policy does
not replace network egress controls or scanner isolation.

## Operator workflow

1. Register the target and review its scope, exclusions, dates, restrictions
   and exploitation permission.
2. Open **Scenarios**, choose a version and bind its inputs to that target.
3. Select **Review scenario plan**. Inspect commands, required tools and ATT&CK
   references, then create the campaign. Changing an input clears the preview.
4. Open **Plan** and approve eligible commands. Waiting and skipped branches
   cannot execute. The scenario plan stays fixed to its version.
5. Analyze each phase after its eligible steps finish. A phase containing only
   skipped branches can advance without inventing execution evidence.
6. Open **Workflow** to inspect dependencies, control the campaign, import
   telemetry and record cleanup review. Pause cancels active and queued work;
   resuming requires individual re-approval of cancelled attempts. Stop is final
   for that run.
7. After all phases are analyzed and executed steps have cleanup records,
   complete the campaign and publish its report.
8. Use **Create retest campaign** to repeat the same scenario and bindings.
   Execution records and verdicts start empty. The comparison appears after
   both runs have the same analyzed phases.

Campaign completion records that the workflow was reviewed and closed. It does
not mean every objective succeeded. Failed tools, skipped branches,
inconclusive objectives and unevaluated detection coverage remain visible.
Cleanup records are explicit operator attestations, not automatic comparison
of the target filesystem. Retries require a new cleanup record for that attempt.
A prerequisite cannot be retried after a dependent step has executed; use a
retest to preserve the recorded branch history.

## Scope boundaries

Bare hosts/CIDRs authorize host-level work. A bare `host:port` is restricted to
that port. Full HTTP(S) URLs additionally bind the scheme and path prefix.
Port-only scope cannot authorize host discovery or a default Nmap scan;
explicit TCP port scans require `-Pn` and must fit all authorized ports. Deterministic fallback
plans are filtered through the same policy and retain HTTPS and URL paths.

Every scenario command is checked during preview/creation, at approval and
again in the worker. A discovered host or input binding never expands scope.
Imported scenarios cannot install plugins, submit shell source or bypass the
tool allowlist. Scanner behavior beyond understood command arguments remains
subject to the existing [security boundaries](priority_security_fixes.md).

## Scenario format

This example works with native curl and can assess any explicitly scoped URL:

```json
{
  "schema_version": 1,
  "id": "team.http-review",
  "version": "1.0.0",
  "name": "HTTP response review",
  "description": "Observe a designated application response.",
  "inputs": {
    "endpoint": {"type": "url", "label": "Application endpoint"}
  },
  "steps": [
    {
      "id": "response",
      "technique": "http.headers@1.0.0",
      "inputs": {"url": "{{endpoint}}"},
      "verify": {"kind": "http_response", "endpoint": "{{endpoint}}"}
    }
  ]
}
```

Input types are `url`, `host`, `ports` and `parameter`. Bindings replace whole
values, not substrings inside shell commands. Technique versions are explicit.
Steps must be in phase order and dependencies must reference earlier IDs;
duplicate IDs, cycles, unknown adapters and mismatched input types are rejected.
An objective must match its node's technique and bound target. Response and
injection objectives use that node's execution; a database-banner objective
requires its own banner evidence and may use prior injection confirmation.

Use `depends_on: [{"step": "response", "condition": "succeeded"}]` to branch.
Conditions are `succeeded`, `failed`, `completed` and `verified`. A verified
dependency must have an objective in an earlier phase. An optional
`stop_on_failure: true` prevents further steps until the failure is resolved.

Changing a published workflow requires a new version. Existing runs retain
their definition, bindings, definition digest and compiled-plan digest.

## Extending techniques and objectives

Add a reviewed `Technique` to `modules/techniques.py`. Its adapter declares the
tool, phase, input types, argument template, ATT&CK references and cleanup
instructions. The existing command policy must independently support the
operation. Scenario authors cannot expand the command policy.

Add objective validation and parsing in `modules/objective_adapters.py` and
the evaluation dispatcher in `campaign_objectives.py`. A verifier must locate
the exact endpoint/resource, use approved successful execution originals,
honor analyzed phases, and return execution/attempt/hash receipts. Include
positive, negative, failed-tool, wrong-resource and missing-evidence cases.
Never use model-authored finding text as proof.

## API reference

All routes require `X-API-Key`. Mutation requests carry ordinary JSON unless
otherwise documented.

| Method/path | Purpose |
| --- | --- |
| `GET /framework/techniques` | Installed technique versions and input schemas |
| `GET /framework/scenarios?offset=0&limit=30` | Built-in and workspace versions |
| `GET /framework/scenarios/{id}/{version}` | Export a definition |
| `POST /framework/scenarios` | Publish an immutable definition |
| `POST /framework/preview` | Bind inputs, check policy and inspect commands/tools |
| `POST /framework/assessments` | Create a scenario campaign |
| `GET /framework/workers` | Worker heartbeats, local tools and active jobs |
| `GET /assessments/{id}/framework` | Derived workflow, cleanup and detection state |
| `POST /assessments/{id}/control` | Pause, resume, stop or complete |
| `POST /assessments/{id}/cleanup` | Record review for an executed node |
| `POST /assessments/{id}/telemetry` | Import up to 100 events per batch |
| `GET /assessments/{id}/framework/events` | Paginated framework history |
| `POST /assessments/{id}/retest` | Create a fresh run with matching inputs |
| `GET /assessments/{id}/framework/compare/{baseline}` | Compare matching analyzed runs |
| `GET /team/me` | Current credential identity and role |
| `GET /team/credentials` | Administrator credential inventory |
| `POST /team/credentials` | Create a named credential; key returned once |
| `DELETE /team/credentials/{id}` | Revoke a credential |

Preview/create body: `scenario_id`, `version`, `target_id`, `bindings` and
optional `objective`. Control body: `workflow_revision`, `action` and `note`.
Cleanup body: `workflow_revision`, `node_id` and `note`. Use the latest revision
returned by the framework endpoint; a stale mutation returns 409. Revision
numbers may advance by more than one transaction.

Telemetry body has `workflow_revision` and an `events` array. Each event has:

```json
{
  "execution_id": 4,
  "attempt": 1,
  "source": "security-tool-export",
  "external_id": "source-event-id",
  "event_type": "alert",
  "observed_at": "2026-11-10T12:00:00Z",
  "summary": "Describe the actual recorded event"
}
```

`event_type` is `alert`, `observation` or `reviewed_no_alert`. References must
match a finished current attempt in this assessment. The service adds its
evidence hash. Timestamps must include a timezone and lie between execution
start and current time. Source/event IDs are deduplicated within the campaign.
There is a 2,000-event campaign limit. Retried attempts do not inherit prior
detection results. First-alert delay uses the supplied event timestamp; it is
not a measured analyst-response or incident-resolution time.

Roles share one workspace; they do not provide tenant or per-client data
isolation. Run separate deployments/databases when that isolation is needed.
The original operator key remains the bootstrap administrator. Viewer keys
cannot mutate; operator keys cannot change settings, administer credentials,
reset the workspace or reveal originals. Only digests of named keys are stored.
