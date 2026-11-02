# Backend review — November 2, 2026

The three substantial changes identified in this review were approved and
implemented. The framework retains FastAPI, SQLAlchemy, SQLite, and the existing
execution queue. The sections below retain the original reproductions and
describe the implemented fixes. Upgrade and raw-access details are in
[Protected evidence and workflow upgrades](protected-evidence-upgrade.md).

## Approved major changes implemented

### 1. Enforce inherited scope when promoting a discovered host — critical

**Reproduced:** an assessment authorized only for `192.0.2.10` accepted promotion
of a merely discovered `198.51.100.20`. The API returned 200 and created a child
target whose authorized scope was `198.51.100.20`. These are synthetic test
addresses; no network connection or command was made.

Previously, `main.promote_host` checked lab mode and campaign membership but
omitted parent scope and compromise-state checks. Discovery output is not
authorization.

**Implemented:**

- Validate the destination against the parent's allowed and excluded scopes
  before creating either the child target or assessment.
- Require the evidence/state promised by the promotion action; reject a host
  that has only been discovered.
- Preserve restrictions and never convert a URL/path/port-limited permission
  into unrestricted access to a whole host. Refuse promotion when a narrower
  child scope cannot be represented safely.
- Make duplicate promotion atomic so concurrent requests cannot create two
  children. Add denial tests for out-of-scope, excluded, unproven, and narrowly
  authorized destinations, plus concurrent promotion.

This changes which promotion requests are accepted. It does not expand tools,
execution privileges, or automatic approval.

### 2. Separate protected raw evidence from redacted output — high

**Reproduced:** a synthetic credential was encrypted in `Loot.secret_encrypted`,
but the same value appeared in the ordinary execution-evidence response and
the generated HTML report, without calling the audited credential-reveal
endpoint. Encrypting the extracted credential alone left plaintext copies
in scanner transcripts. Earlier tests seeded credentials separately from output
and did not cover this case.

Relevant paths are `modules.jobs.run_execution`, `main.get_execution_evidence`,
`main.analyze_assessment`, `modules.footholds.ingest_execution`, and reporting.
The implemented protection includes live output and provider inputs.

**Implemented:**

- Retain original transcripts as encrypted evidence with controlled, audited
  access, preserving the original evidence hashes.
- Redact known credentials and recognized credential-bearing output before
  exposing it in live output, ordinary evidence, findings, recommendations,
  provider requests, and report exports.
- Keep parsers able to inspect protected originals so redaction does not destroy
  verification or credential extraction.
- Add a migration/backfill strategy for existing transcripts, attempts, and
  exported report versions. Existing report hashes must not silently change.
- Test chunk-split secrets, failure output, retries, exports, and audited access.

Migration `0005_protected_workflows` adds encrypted execution/attempt originals,
original output hashes, restricted legacy report storage and report pointers.
Legacy reports retain their original digests and become available through
audited access; regenerating produces a redacted public version. The UI explains
why legacy downloads are retired. Encryption-key creation is atomic, and raw
decryption refuses missing or incorrect keys.

### 3. Publish assessment state and reports atomically — high

Two different failure paths were reproduced:

| Trigger | Observed result |
| --- | --- |
| Edit the plan while a report is being rendered | HTTP 200; the assessment had plan version 2, but the new report cited version 1 and set the assessment back to `reported`. |
| Inject an evidence-ingestion failure during analysis | HTTP 500; five findings remained saved, status remained `analyzing`, and no phase was marked analyzed. |

Previously, analysis and ingestion committed intermediate findings, and report
publication omitted revalidation. Manual/automatic phase drafting and autopilot
now participate in the same assessment revision contract.

**Implemented:**

- Establish one assessment revision/claim contract for plan, phase, execution,
  analysis, and report mutations; reject stale requests with a clear conflict.
- Compute slow provider/report work from an immutable snapshot, then verify its
  revision and execution attempts before committing results.
- Make the caller own the transaction. Change persistence helpers to flush
  rather than commit intermediate analysis state.
- Stage report files, publish the version only after validation, and clean up
  failed staging files without losing an existing valid report.
- Add fault-injection and concurrent-request tests for partial analysis, stale
  reports, duplicate drafts, and retries after failures.

The assessment mapper versions ORM writes, and conditional claims guard bulk
mutations and slow-operation publication. Analysis, verification, campaign
ingestion and automatic drafting commit together. Autopilot commits its local
transition and bookkeeping atomically, then computes advisory proposals without
holding the write lock and checks the revision before saving them. Current
reports are served through a database pointer to an immutable version; stale
rendering cannot overwrite another report. File retirement happens after commit.

## Contained fixes implemented during this review

- Editing an unexecuted later-phase command invalidates that phase and its
  dependents, preserving earlier findings and prerequisite analysis.
- An unchanged plan save preserves analysis and the existing report. Editing
  only the rationale preserves evidence and requires report regeneration.
- Requesting a reconnaissance re-draft returns a controlled 409 response
  instead of dereferencing a missing prerequisite and returning 500.
- A malformed non-ASCII operator key returns 401 rather than crashing the
  constant-time comparison. Normal valid-key authentication is unchanged.
- Campaign deletion removes dependent credentials, footholds, host inventory,
  and stale child links in foreign-key order. Deleting a parent with children
  returns 409 before removing its evidence. Workspace reset removes the whole
  graph correctly with production's `autoflush=False` sessions.

The existing test that expected later-phase edits to erase all findings was
corrected. It now verifies both preservation for a later-phase edit and actual
invalidation when new reconnaissance work is added.

## Verification and limits

After the approved major changes, the full backend suite passed **412 tests**.
A subsequent focused run passed **59 tests**, including malformed promotion
scope handling. The external-worker backfill gate has a separate startup
regression. New coverage in `backend/test_protected_workflows.py` exercises
concurrent promotion/drafting, stale analysis/report publication, analysis and
autopilot rollback, encrypted retry originals, stream chunk boundaries,
provider-input redaction, wrong keys, atomic key creation, legacy backfill and
unchanged execution of approved commands. Frontend validation passed **24
tests**, the production build and lint. The two backend warnings concern the
existing Starlette/httpx deprecation and an unwritable local pytest cache.

The baseline backend suite passed: **378 tests**. Additional regression tests
are in `backend/test_backend_review.py`. After the contained fixes, the full
suite passed: **386 tests**, with two existing warnings. The eight focused
regression cases also passed, and whitespace checks passed for the changed
tracked implementation/test files. The major findings above were reproduced
with isolated SQLite storage, enforced foreign keys, synthetic output, and
injected failures/interleavings. No live operator database or credentials were
used, and no scanner, SSH connection, or provider request was executed.

The local reproduction script is
`backend/.runlogs/backend-audit/probes.py`; recorded results are in
`backend/.runlogs/backend-audit/run-ddbb2bf7/findings.json`.

Review covered API lifecycle/policy gates, queue claims/cancellation/recovery,
scope inheritance, settings/authentication, evidence handling, analysis,
reports, persistence/migrations, and deployment definitions. This is not proof
of live VM/tool compatibility or a production container deployment.

Before scaling workers, the shared SSH tmux pane needs a cross-process ownership
mechanism; its current `asyncio.Lock` protects only one process. Newly installed
campaign packages are also unpinned in the Dockerfile. These are deployment
follow-ups, separate from the reproduced issues above.
