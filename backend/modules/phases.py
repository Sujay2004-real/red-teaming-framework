"""The pentest phase model shared by the planner, policy engine, API, and UI.

An assessment now walks the full authorized-testing lifecycle instead of
stopping after scanning:
  scoping -> recon -> vuln_analysis -> exploitation -> post_exploitation -> reporting

`scoping` and `reporting` are bookends rather than command phases: scoping
happens before an assessment exists (letter import, target registration) and
reporting after the last command has run, but both appear in the phase
stepper so the UI can show the whole engagement.

Phases after recon are drafted from the *previous* phase's findings: the
exploitation plan proposes verification steps for what the analysis actually
found, and post-exploitation proposes bounded impact proof only for what
exploitation verified. The plan is a single append-only step list, with each
step tagged by the phase that drafted it.
"""

# Ordered phases, the single source of truth for both backend and frontend.
PHASES = ('scoping', 'recon', 'vuln_analysis', 'exploitation', 'post_exploitation', 'reporting')

# Phases whose steps appear in the plan. Scoping precedes the assessment and
# reporting follows the last command, so neither owns plan steps.
PLAN_PHASES = ('recon', 'exploitation', 'post_exploitation')

PHASE_LABELS = {
    'scoping': 'Scoping & authorization',
    'recon': 'Reconnaissance & enumeration',
    'vuln_analysis': 'Vulnerability analysis',
    'exploitation': 'Exploitation',
    'post_exploitation': 'Post-exploitation',
    'reporting': 'Reporting',
}

# Phase that a step tagged with a given phase advances the assessment into
# once all its enabled steps are executed and analyzed. Recon output analyzed
# is the vulnerability-analysis phase; exploitation output analyzed is the
# post-exploitation evidence base; post-exploitation output analyzed means the
# engagement evidence is complete and only the report remains.
ANALYSIS_ADVANCES_TO = {
    'recon': 'vuln_analysis',
    'exploitation': 'post_exploitation',
    'post_exploitation': 'reporting',
}

# The phase a phase-plan endpoint may draft, keyed by the phase that must be
# analyzed first.
NEXT_DRAFTABLE_PHASE = {
    'vuln_analysis': 'exploitation',
    'post_exploitation': 'post_exploitation',
}

# Tools that only an engagement letter authorizing controlled exploitation
# permits. A target without that authorization refuses these commands at
# policy review, exactly like a per-target tool restriction.
EXPLOITATION_GATED_TOOLS = {'sqlmap', 'msfconsole'}

# curl is a recon tool until it carries a request body: a payload turns the
# request into a proof-of-concept, which is exploitation-grade and needs the
# letter's authorization. Keys are tools; values are the flags that, when
# present, make the command exploitation-grade.
PAYLOAD_FLAGS = {'curl': {'-d', '--data', '--data-ascii', '--data-binary',
                          '--data-raw', '--data-urlencode', '-F', '--form',
                          '--form-string', '--json'}}

# Tools that exist only on the attacker VM. The local executor refuses them
# with a clear error rather than failing with a missing-binary traceback.
VM_ONLY_TOOLS = {'msfconsole'}


def phase_index(phase):
    try:
        return PHASES.index(phase)
    except ValueError:
        return None


def validate_phase(phase):
    """Return the phase name when it is a real phase, else None."""
    return phase if phase in PHASES else None


def is_plan_phase(phase):
    return phase in PLAN_PHASES
