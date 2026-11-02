// Constants and small pure helpers shared across the panels. The engagement
// lifecycle mirrors backend/modules/phases.py: scoping and reporting are
// bookends, the three middle phases own plan steps.

// Only used until /capabilities answers. The backend policy engine owns the
// real list, so a tool hardcoded here that policy rejects would just produce
// a step that fails at approval time.
export const FALLBACK_CAPABILITIES = [{
  id: 'tools',
  tools: ['nmap', 'traceroute', 'dig', 'nslookup', 'curl', 'whatweb', 'sslscan', 'nuclei'].map(name => ({ name })),
}]

export const emptyStep = tool => ({ tool: tool || 'nmap', command: '', reason: '', enabled: true })

// The backend falls back to a built-in plan for four different reasons; saying
// which one keeps a provider outage from looking like a successful AI plan.
export const PLAN_SOURCE_NOTE = {
  'ai-filtered': 'Plan drafted by the configured AI provider and cleared by policy review.',
  'default-unconfigured': 'No AI provider is configured, so the built-in default plan was used. Add a base URL, model name, and API key to enable AI planning.',
  'default-provider-error': 'The AI provider could not be reached, so the built-in default plan was used.',
  'default-policy-rejected': 'Every AI-suggested command failed policy review, so the built-in default plan was used.',
  user: 'Using the plan you supplied.',
}

export const samePlan = (a, b) => JSON.stringify(a || []) === JSON.stringify(b || [])

// The engagement lifecycle the stepper visualises.
export const PHASES = [
  { key: 'scoping', label: 'Scoping & authorization', caption: 'Import the letter and register authorized targets' },
  { key: 'recon', label: 'Reconnaissance', caption: 'Enumerate services, versions and exposures' },
  { key: 'vuln_analysis', label: 'Vulnerability analysis', caption: 'Correlate and score the recon output' },
  { key: 'exploitation', label: 'Exploitation', caption: 'Verify the findings with controlled proof-of-concepts' },
  { key: 'post_exploitation', label: 'Post-exploitation', caption: 'Bounded impact proof on verified findings' },
  { key: 'reporting', label: 'Reporting', caption: 'Deliver the client report' },
]
// The lab-only campaign phases. They sit between post-exploitation and
// reporting, and exist only for a target in aggressive lab mode; the backend
// refuses to draft or execute them anywhere else, so the UI never offers them
// for a production target.
export const CAMPAIGN_PHASES = [
  { key: 'credential_validation', label: 'Credential validation', caption: 'Prove the recovered credentials actually authenticate' },
  { key: 'lateral_movement', label: 'Lateral movement', caption: 'Re-use proven access across the authorized scope' },
  { key: 'impact', label: 'Impact & objective proof', caption: 'Demonstrate the objective through the access obtained' },
]
export const ALL_PHASES = [...PHASES.slice(0, 5), ...CAMPAIGN_PHASES, PHASES[5]]
// The phases an engagement in this mode walks. Mirrors phases.phase_chain().
export const engagementPhases = aggressive => (aggressive ? ALL_PHASES : PHASES)
export const PHASE_LABEL = key => ALL_PHASES.find(p => p.key === key)?.label || key
export const PLAN_PHASES = ['recon', 'exploitation', 'post_exploitation',
                            'credential_validation', 'lateral_movement', 'impact']

// The same formats and size cap the backend enforces on uploads, checked
// client-side so a wrong pick gets a readable message instead of silence or
// a raw 4xx from the server.
export const ALLOWED_UPLOAD_SUFFIXES = ['.txt', '.md', '.pdf', '.docx']
export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024
export const fileSuffix = name => (name.match(/\.[^.]+$/) || [''])[0].toLowerCase()

// An objective drafted from the letter keeps the client's own framing: a
// baseline-restricted target says so plainly, a full assessment carries the
// letter's numbered objectives.
export const suggestedObjective = (brief, target) => {
  const goals = (brief?.objectives || []).map(o => o.replace(/^[\d.]+\s*/, '')).join('; ')
  const baseline = (target.assessment_type || '').toLowerCase().includes('baseline')
  const headline = baseline
    ? `Baseline assessment of ${target.name}: ${target.assessment_type}`
    : `Assess ${target.name} per engagement ${brief?.engagement_ref || ''}`
  return (goals ? `${headline}. Objectives: ${goals}` : headline).slice(0, 1000)
}
