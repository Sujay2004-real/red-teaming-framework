# Changelog

## 4.0.0 - 2026-11-10

- Added reusable, versioned security-assessment scenarios with typed inputs,
  immutable plans, dependency branches, previews, imports and exports.
- Added campaign pause, resume, stop, cleanup review, completion and controlled
  retest comparisons.
- Added objective evidence, detection telemetry, named team credentials, worker
  inventory and shared SSH execution leases.
- Hardened provider credential handling when endpoints change.
- Extended reports with scenario, objective, cleanup, telemetry and provenance
  data while retaining failed, skipped and unevaluated outcomes.
- Added migration `0006_framework` and updated the operator interface for the
  framework workflow.
- Reduced the published repository to product source, deployment definitions,
  tests and maintained operator documentation. Local demos, presentations,
  generated PDFs and evaluation fixtures are excluded from the release.
