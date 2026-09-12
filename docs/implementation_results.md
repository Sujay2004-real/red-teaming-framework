# Implementation Results — material for the final project report

This document collects the measured facts of the Phase-2 implementation, so the
final report's chapters can cite numbers instead of assertions. Each section
maps to the report chapter it belongs in.

## Chapter 4/6 (architecture) — what was actually built

| Layer | Module | Lines | Responsibility |
|---|---|---|---|
| API | `main.py` | ~1,480 | 21 REST endpoints, phase lifecycle, execution approval |
| Auth | `modules/api_auth.py` | 89 | Operator API-key gate (env-chosen or generated, digest-stored) |
| Policy | `modules/policy_engine.py` | ~640 | Per-tool flag allowlists, scope/CIDR checks, letter-gated exploitation, msf script validation |
| Execution | `modules/executor.py` | 161 | `create_subprocess_exec` (no shell), timeouts, output caps, env sandboxing |
| VM engine | `modules/ssh_executor.py` | 383 | Kali VM over SSH + tmux, per-run attestation |
| Analysis | `modules/analyzer.py` | ~850 | 9 deterministic tool parsers (incl. the OWASP ZAP passive baseline), scoring, dedup |
| Planning | `modules/planner.py`, `exploit_planner.py` | 185 + 253 | Default/subnet plans; findings → verification steps |
| Adaptivity | `modules/next_steps.py` | 503 | Bounded engagement-state digest → ranked, policy-checked proposals |
| Reasoning | `modules/attack_paths.py` | 260 | Finding graph → attack paths; grounded AI narratives |
| Reporting | `modules/reporter.py` + template | 33 + ~200 | Client HTML report with phases, verification, attack paths, audit trail |
| Frontend | `src/App.jsx` + 12 components | ~2,700 | Single-page control center |

**Total: ~9,300 lines of backend Python, ~2,700 lines of frontend, 233 automated tests
(all passing, pytest runtime ≈ 12 s).**

## Chapter 7 (methodology) — the loop, as actually implemented

The report's Chapter 4 promised "the planner recommends the next step only after the
previous output has been reviewed." That promise is now implemented at two levels:

1. **Level 1 — auto-draft on analysis.** When a phase's outputs are analyzed and the
   analysis unlocks the next phase, the backend drafts that phase's plan immediately
   (the same policy-gated drafting the button used to trigger). A refusal — e.g. the
   letter not authorizing exploitation — is returned as a note with the reason,
   surfaced in the UI feed.
2. **Level 2 — automatic recommendation batches.** Every finished execution schedules
   a proposal batch computed from the observed engagement state (bounded digest of
   findings + audit trail). Batches persist as engagement evidence (`recommendations`
   table), name the execution that triggered them, include the policy engine's
   refusals with reasons, and are capped at 25 per engagement. A batch becomes plan
   steps only through the ordinary plan-save path — the loop proposes; it never acts.

## Chapter 8 (evaluation) — how to produce the numbers

`backend/eval_harness.py` runs the full phased flow N times per target and emits a
JSON summary (mean/stdev/min/max per metric):

- wall-clock per phase (planning / execution / analysis / reporting)
- commands drafted vs executed, failures
- findings, severity mix, verification outcomes
- policy refusals (count + reasons)
- checklist recall against ground truth (`--checklist`, Metasploitable2 list included)

The ablation (`--ablate`) runs the same arms twice — deterministic analyzer, then the
configured AI provider — and reports the comparison (findings mean, wall-clock mean,
recall mean per arm), in the shape of PentestGPT's Figure 8 ablation.

Suggested evaluation protocol for the report (3 targets × 3 runs):

```
# deterministic + AI arms, Metasploitable2 with its documented ground truth:
venv\Scripts\python.exe eval_harness.py --targets "Meta2=192.168.56.101" --exploit \
    --checklist checklists/metasploitable2.txt --runs 3 --ablate --out eval_meta2.json
# the real application (letter-driven, no exploitation), e.g. against any
# authorized self-hosted target:
venv\Scripts\python.exe eval_harness.py --letter JuiceBox_Security_Assessment_Request.pdf --runs 3 --out eval_results.json
```

Run these once the lab VMs are up, and paste the `summary` / `comparison` blocks into
Chapter 8 as tables — they replace the estimated comparison table with measurements.

## Chapter 9 (safety & governance) — controls as implemented

| Control | Implementation |
|---|---|
| Operator authentication | `X-API-Key` on every route except `/health`; SHA-256 digest at rest; env override |
| Command allowlist | Per-tool flag enumeration, fail-closed (13 tools incl. OWASP ZAP passive baseline) |
| Scope enforcement | Hostname suffix / CIDR `subnet_of` membership; subnet sweeps bounded to 256 addresses |
| Exploitation gate | Letter authorization required for sqlmap/msfconsole/curl-with-body, at plan, draft and approval time |
| Active scanning | ZAP's active-scan, config-file and daemon-option flags refused by the allowlist by design |
| Human-in-the-loop | Per-step `approved: true`; executed steps immutable; recommendation loop read-only |
| Audit trail | Every command, output, attempt and attestation persisted; auto-recommendation batches kept as evidence |
| Secrets | Fernet at rest; never returned by the API; no env-seeded credentials |
| Prompt-injection | Tool output stripped of control chars, confined to untrusted blocks; authorization never depends on it |
| Attack-path narratives | AI citations verified against real finding ids; hallucinated provenance falls back to deterministic text |

## Deviations from Phase 1, and the design argument for each

1. **OWASP ZAP enters as the passive baseline, not the active scanner.** The report
   named ZAP alongside Nmap and Nuclei. It is integrated — but as ZAP's own CI
   baseline wrapper in passive mode, because passive crawling is reconnaissance
   (audit what the application serves) while active scanning sends attack payloads,
   which under this framework's own model is exploitation-grade and belongs behind
   the letter's authorization. The active scanner's flags (`-a`, config files, `-z`
   daemon options) are refused by the policy engine by design.
2. **The recommendation loop is automatic in proposing, manual in acting.** Full
   autonomy was rejected deliberately — every paper in the Phase-1 survey converges
   on that line, and the framework's contribution is demonstrating that the loop can
   get faster without crossing it.

## Verification performed (2026-09-12)

- pytest: **233 passed** (0.13 s–12 s per file; full suite ≈ 12 s)
- ESLint: 0 errors; production build: 32 modules, 77 kB gzipped JS
- Live end-to-end smoke run (backend on Windows, no lab): full phased lifecycle
  completed — letter import → 8-step recon plan (incl. `zap-baseline.py`) → execution →
  analysis → **auto-drafted exploitation plan (2 steps)** → execution → analysis →
  **auto-drafted post-exploitation plan (2 steps)** → execution → analysis → report;
  7 automatic recommendation batches recorded, each tied to its trigger execution;
  auth gate verified (401 without key, 200 with).

## Suggested citation corrections for the Phase-1 literature table

Verify every 2026-dated survey entry resolves on Google Scholar before submission;
replace any that do not with verifiable 2024–2025 work (PentestGPT/Deng et al.,
Happe & Cito, AutoPenBench/Xu et al., and the CAI framework/Mayoral-Vilches are all
real and already adjacent to the table).
