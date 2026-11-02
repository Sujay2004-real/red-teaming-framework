"""The pentest phase model shared by the planner, policy engine, API, and UI.

An assessment walks the authorized-testing lifecycle instead of stopping after
scanning. The base chain is:

  scoping -> recon -> vuln_analysis -> exploitation -> post_exploitation -> reporting

An engagement whose target is in aggressive lab mode walks the full kill chain
instead, inserting three lab-only phases after post-exploitation:

  ... -> post_exploitation -> credential_validation -> lateral_movement -> impact -> reporting

post_exploitation enumerates through the foothold the exploitation phase opened
and recovers credentials; credential_validation proves those recovered secrets
actually authenticate; lateral_movement re-uses them against the other hosts in
scope; impact proves the engagement objective end to end. All three are gated on
aggressive lab mode exactly like the tools they drive: the base chain and the
production-target allowlist are untouched by their existence.

`scoping` and `reporting` are bookends rather than command phases: scoping
happens before an assessment exists (letter import, target registration) and
reporting after the last command has run, but both appear in the phase stepper
so the UI can show the whole engagement.

Phases after recon are drafted from the *previous* phase's findings: the
exploitation plan proposes verification steps for what the analysis actually
found, and each later phase proposes work for what the phase before it proved.
The plan is a single append-only step list, with each step tagged by the phase
that drafted it.
"""

# Ordered phases: the base, non-lab engagement lifecycle. This is what a
# production target (no aggressive lab flag) walks, and it is unchanged.
BASE_PHASES = ('scoping', 'recon', 'vuln_analysis', 'exploitation',
               'post_exploitation', 'reporting')

# The phases the full kill chain adds, in order, after post-exploitation. They
# are lab-only: a target without aggressive_lab never reaches them, and the
# policy engine refuses the tools they drive regardless of what a plan says.
CAMPAIGN_PHASES = ('credential_validation', 'lateral_movement', 'impact')

# The base phase tuple, kept as the canonical "all phases" name for the
# non-lab engagement so existing callers keep working unchanged.
PHASES = BASE_PHASES


def phase_chain(aggressive=False):
    """Every phase of the engagement, in order, for its mode."""
    if not aggressive:
        return BASE_PHASES
    return ('scoping', 'recon', 'vuln_analysis', 'exploitation', 'post_exploitation',
            'credential_validation', 'lateral_movement', 'impact', 'reporting')


# Phases whose steps appear in the plan. Scoping precedes the assessment and
# reporting follows the last command, so neither owns plan steps.
PLAN_PHASES = ('recon', 'exploitation', 'post_exploitation')
CAMPAIGN_PLAN_PHASES = CAMPAIGN_PHASES
# Every phase tag a plan step may legally carry. The plan validator uses this;
# eligibility to *draft* a phase is decided per mode by plan_phases().
ALL_PLAN_PHASES = PLAN_PHASES + CAMPAIGN_PLAN_PHASES


def plan_phases(aggressive=False):
    """The plan phases available to an engagement in this mode, in order."""
    return ALL_PLAN_PHASES if aggressive else PLAN_PHASES


PHASE_LABELS = {
    'scoping': 'Scoping & authorization',
    'recon': 'Reconnaissance & enumeration',
    'vuln_analysis': 'Vulnerability analysis',
    'exploitation': 'Exploitation',
    'post_exploitation': 'Post-exploitation',
    'credential_validation': 'Credential validation',
    'lateral_movement': 'Lateral movement',
    'impact': 'Impact & objective proof',
    'reporting': 'Reporting',
}

# Phase that a step tagged with a given phase advances the assessment into
# once all its enabled steps are executed and analyzed. Recon output analyzed
# is the vulnerability-analysis phase; exploitation output analyzed is the
# post-exploitation evidence base; and once the last plan phase that a mode
# uses has been analyzed, only the report remains.
_ANALYSIS_ADVANCES_TO = {
    'recon': 'vuln_analysis',
    'exploitation': 'post_exploitation',
    'post_exploitation': 'reporting',
}

_CAMPAIGN_ANALYSIS_ADVANCES_TO = {
    'recon': 'vuln_analysis',
    'exploitation': 'post_exploitation',
    'post_exploitation': 'credential_validation',
    'credential_validation': 'lateral_movement',
    'lateral_movement': 'impact',
    'impact': 'reporting',
}

# Kept as the base mapping for callers that do not know the target's mode.
ANALYSIS_ADVANCES_TO = _ANALYSIS_ADVANCES_TO


def analysis_advances_to(phase, aggressive=False):
    """The phase this phase's analysis unlocks, or None."""
    mapping = _CAMPAIGN_ANALYSIS_ADVANCES_TO if aggressive else _ANALYSIS_ADVANCES_TO
    return mapping.get(phase)


# The phase a phase-plan endpoint may draft, keyed by the phase the assessment
# currently sits in.
_NEXT_DRAFTABLE_PHASE = {
    'vuln_analysis': 'exploitation',
    'post_exploitation': 'post_exploitation',
}

_CAMPAIGN_NEXT_DRAFTABLE_PHASE = {
    'vuln_analysis': 'exploitation',
    'post_exploitation': 'post_exploitation',
    'credential_validation': 'credential_validation',
    'lateral_movement': 'lateral_movement',
    'impact': 'impact',
}

NEXT_DRAFTABLE_PHASE = _NEXT_DRAFTABLE_PHASE


def next_draftable_phase(phase, aggressive=False):
    """The phase that may be drafted from the assessment's current phase."""
    mapping = _CAMPAIGN_NEXT_DRAFTABLE_PHASE if aggressive else _NEXT_DRAFTABLE_PHASE
    return mapping.get(phase)


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


def phase_index(phase, aggressive=False):
    try:
        return phase_chain(aggressive).index(phase)
    except ValueError:
        return None


def validate_phase(phase, aggressive=False):
    """Return the phase name when it is a real phase for this mode, else None."""
    return phase if phase in phase_chain(aggressive) else None


def is_plan_phase(phase):
    """True when a plan step may carry this phase tag at all.

    This is the *syntax* check the plan validator applies, so it accepts every
    phase either mode can produce. Whether a given engagement may actually
    draft a lab-only phase is decided per mode by plan_phases().
    """
    return phase in ALL_PLAN_PHASES


def preceding_plan_phase(phase, aggressive=False):
    """The plan phase whose analyzed results this phase is drafted from."""
    order = plan_phases(aggressive)
    if phase not in order:
        return None
    index = order.index(phase)
    return order[index - 1] if index > 0 else None
