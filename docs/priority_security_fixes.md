# Priority security fixes

Updated for release 4.0.0. See the
[upgrade notes](protected-evidence-upgrade.md) for deployment requirements.

## Container contents

The backend image copies its API/worker entrypoints, database/models modules,
migration configuration/tree and the `modules/` source tree, including report
templates. Its build context excludes
runtime data, encryption keys, environment files, reports, logs, virtual
environments and pytest artifacts.

Rebuild the backend image to apply these changes to Docker deployments. Existing
images and exported archives are not rewritten by editing the Dockerfile.

## Command arguments

The policy checks values in separated, attached (`--threads=3`) and supported
bundled options. Every occurrence is checked; a later safe value cannot hide an
earlier unsafe one. Numeric limits live in `backend/modules/command_values.py`.

- Secondary sqlmap URLs (`--csrf-url`, `--second-order`) are scope-checked.
- Excessive concurrency, retry counts, rates, durations and invalid ports fail.
- File-reading curl data/form options, custom Nuclei template sources, sqlmap
  tamper scripts, dig key files and HTTP routing override headers are refused.
- curl redirect following is refused. WhatWeb requires `--follow-redirect never`,
  Nuclei requires `-dr`, and sqlmap requires `--ignore-redirects`. Default plans and
  AI planning instructions include these controls.
- Nmap `-A` is refused because it also enables NSE scripts.
- Metasploit scripts require an explicit scoped target before each module runs,
  bounded numeric options, and exactly one resource-script option.
- SSH execution quotes parsed arguments before typing them into the remote shell,
  preserving the local executor's literal argument semantics.

Previously saved commands without required controls receive an explanatory policy
refusal. Review and update unexecuted steps before approving them. Argument checks
do not provide a general egress firewall for scanner internals or DNS changes.

## Verification

Verification is derived independently from successful scanner executions, even
when the findings analyzer uses an AI provider. Currently the confirming adapter
recognizes explicit sqlmap SQL-injection results. HTTP 200 responses, banners,
exploit database matches and AI-authored evidence cannot establish this verdict.

Links require the same vulnerability category, scheme, hostname, port,
case-sensitive path and parameter. Other query parameters must also match.
Hostname case and default ports are normalized. The primary endpoint comes from
the executed command. Unknown endpoints, ambiguous URLs, secondary-URL runs,
nonzero exits and tentative or negated output cannot establish proof.

Replacing exploitation analysis clears dependent verification claims. New
post-exploitation plans require a verified SQL-injection endpoint; there is no
fallback to an unverified target. These rules apply to new analyses; historical
stored findings and exported reports are not automatically reclassified.

## Evidence and workflow publication

Execution and attempt originals are encrypted. Ordinary output, provider input,
findings and reports use redacted projections; explicit original/loot reveals
commit durable access audits before returning no-store responses. Legacy public
reports are retired, retaining their original encrypted bytes and digests.
Redaction recognizes supported secret formats and known values, not arbitrary
unlabelled secrets.

Analysis, verification, campaign ingestion and phase advancement commit together.
Slow report/provider results are revision-checked before publication. Reports
use immutable versions and a committed current pointer. External workers wait
for schema head and completion of protected-evidence backfill.

Host promotion requires owned evidence and parent host-wide authorization,
honors exclusions and preserves restrictions. URL/path/port-only permission
cannot authorize a whole-host child. Concurrent duplicate promotion is rejected.

Application routes require an operator credential except `/health` and
`/ready`. FastAPI schema/documentation routes are public. Named viewer,
operator and administrator credentials share one workspace; the bootstrap key
remains an administrator.

## Validation

The regression suite covers argument bypasses, unsafe destinations, literal SSH
arguments, cross-host/cross-path verification mismatches, failed runs,
AI-fabricated evidence and the API verification flow. Additional coverage checks
encryption/redaction, audited reveal, legacy adoption, promotion, rollback and
concurrent publication.

Use the isolated commands in [testing](testing.md). Live scanner, VM, provider
and target validation remain deployment tasks.
