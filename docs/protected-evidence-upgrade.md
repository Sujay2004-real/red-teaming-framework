# Protected evidence and workflow upgrades

The November 2 backend fixes add migration `0005_protected_workflows`. Deploy
the matching API and worker code together. Application startup runs the schema
migration and evidence backfill before accepting traffic or starting embedded
jobs. External workers wait for both schema head and completion of that
backfill before claiming work. Keep the existing `REDTEAM_SECRET_KEY` or
`data/.secret_key`; the same key
must be available to the API and every worker. Back up the database, report
directory and key together before upgrading. This development validation used
temporary databases; it did not upgrade the operator's active database.

## Evidence storage and access

Execution stdout, stderr and the approved command have encrypted originals.
Completed attempt archives retain separate encrypted originals. Ordinary
execution records, live output, attempt snapshots, generated findings and
report output contain redacted evidence. SHA-256 provenance uses the original
stdout/stderr pair, not its redacted projection. Internal campaign parsers and
verification can inspect originals; provider analysis receives redacted input.
Known recovered credentials in plans become resolvable `$$loot:<id>$$`
references. Redaction of execution records does not alter the command executed.

Redaction covers recognized Hydra, NetExec, Metasploit credential tables,
hashdump and shadow output, labeled credentials/tokens, private keys, URL
credentials and known recovered values (including common escaped forms).
It does not classify every arbitrary unlabelled string as a secret. Executable
plan source retains operator-authored probe payloads; use loot references for
credentials instead of typing new secrets into command text.

Live output publishes complete redacted lines. It withholds unfinished lines
and stops at the existing buffer limit rather than exposing partial credentials
or dropping the table headers needed to recognize them. The completed execution
retains the executor's bounded original output, including cancellation evidence.

The following operator-authenticated routes provide explicit original access:

| Request | Result |
| --- | --- |
| `POST /assessments/{id}/executions/{execution_id}/evidence/reveal` | Original command, stdout, stderr, attempt and evidence hash |
| Same route with `?attempt=N` | Original archived attempt |
| `POST /assessments/{id}/reports/{version_id}/reveal` | Restricted legacy report as an attachment |
| `GET /assessments/{id}/loot/{loot_id}/reveal` | Existing recovered-credential reveal |

Each successful reveal first commits a durable `evidence_access` audit record
in the recommendation history, then returns a response with `Cache-Control:
no-store`. Authentication uses the existing operator key; invalid operator keys
return 401. Missing/wrong encryption keys or unreadable ciphertext return 409
and never overwrite an original with an
empty value. There is no separate role system in this single-operator app.

## Existing evidence and reports

Startup backfills existing execution and attempt originals, redacts derived
text and retires pre-upgrade HTML reports. Retired reports keep their original
digest and encrypted bytes; their public files are removed after the database
transaction succeeds. Cleanup retries on startup if interrupted. Historical
download routes return 409 for restricted versions. Generate a new report to
obtain a redacted public download. Previously downloaded files and backups are
outside this migration and still contain their original content.

## Workflow conflicts

An assessment has a workflow revision in addition to its editable plan version.
Plan edits, approvals, cancellations, execution completion, campaign ingestion,
promotion, analysis, phase drafting, autopilot and report publication coordinate
through this revision. Competing writes receive 409 and must reload. No scanner
command is retried automatically in response to a workflow conflict.

Analysis saves findings, verification, campaign evidence and phase advancement
in one transaction. An exception restores the earlier state. Report rendering
uses a unique staging file and publishes only after validating its starting
revision. Current downloads resolve the committed immutable report pointer;
the old mutable `report_{id}.html` pathname is no longer the current-report API.
Autopilot's local phase transition is atomic; its advisory provider result is
saved separately only if that committed state is still current.

Host promotion requires an owned host, host-wide permission within the parent
scope and no overlap with exclusions. URL/path/port-only permission cannot
authorize a child whose default recon plan scans the whole host. Promotion
retains the parent's restrictions and refuses duplicate concurrent requests.

## Deployment and verification

See [deployment](deployment.md) for shared storage/key configuration and the
[API reference](api-reference.md) for public and audited evidence routes.
The [testing guide](testing.md) records the 412-test full backend run, the later
59-test focused run, one passing worker-startup regression and 24 frontend
tests. These checks used isolated storage, not the operator's live database.
