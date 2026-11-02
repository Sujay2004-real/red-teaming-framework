# Documentation index

These guides describe the implementation committed in `0ef3689` and this
documentation refresh. The schema head is `0005_protected_workflows`.
Source code and migrations define runtime behavior.

## Current guides

- [Project README](../README.md): overview and quick start.
- [Deployment](deployment.md): Docker/native setup, keys, networking and SSH.
- [API reference](api-reference.md): application routes and request behavior.
- [Backend technical reference](backend_technical_reference.md): components,
  persistence and workflow in plain language.
- [Backend algorithms](backend_algorithms_reference.md): decision procedures and
  transaction boundaries.
- [Algorithms and formulae](backend_algorithms_formulae_reference.md): scores,
  hashes, budgets and evaluation definitions.
- [Evidence upgrade](protected-evidence-upgrade.md): original access and backfill.
- [Security controls](priority_security_fixes.md): enforced checks and limits.
- [Testing](testing.md): commands, recorded runs and live-test scope.
- [Frontend guide](../frontend/README.md): UI architecture and development.
- [Implementation results](implementation_results.md): project-report material.
- [Implementation checklist](implementation-checklist.md): completed work.

## Downloadable references

The PDFs are generated from their corresponding Markdown sources:

| PDF | Source | Generator |
| --- | --- | --- |
| [Backend technical reference](backend_technical_reference.pdf) | [Markdown](backend_technical_reference.md) | `make_backend_reference_pdf.py` |
| [Backend algorithms](backend_algorithms_reference.pdf) | [Markdown](backend_algorithms_reference.md) | `make_algorithms_reference_pdf.py` |
| [Algorithms and formulae](backend_algorithms_formulae_reference.pdf) | [Markdown](backend_algorithms_formulae_reference.md) | `make_backend_algorithms_formulae_pdf.py` |

From the repository root, with ReportLab installed:

```sh
python make_backend_reference_pdf.py
python make_algorithms_reference_pdf.py
python make_backend_algorithms_formulae_pdf.py
```

All three share a renderer so editing Markdown and regenerating keeps them
consistent. The sample client-letter PDF is an independent template generated
by `make_client_request_pdf.py`; it is not an implementation reference.

## Review history

- [November 2 backend review](backend-review-2026-11-02.md) preserves the original
  failures, approved fixes and validation.
- [UI review and demo notes](visual-demo-polish.md) records interface work.
- [Original HTML audit](audit-report.html) is historical. Its original counts,
  findings and suggestions are preserved; use current guides and the checklist
  for today's behavior. Some deployment follow-ups remain, so the archive must
  not be read as a list of universally resolved bugs.

Record test results with their date and scope. Do not replace historical
measurements with estimates or equate mocked tests with live scanner validation.
