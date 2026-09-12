import { useApp } from '../lib/AppContext'

// Two ways into an assessment: from a registered target (the letter import
// path fills objective/requirements for you), or the operator picks targets
// and writes their own engagement prompt.
export default function NewAssessmentPanel({
  targets, briefFilename, brief, mode, setMode,
  assessment, setAssessment, setRequirementFile,
  promptTargetIds, togglePromptTarget, promptText, setPromptText,
  onCreateFromLetter, onCreateFromPrompt,
}) {
  const { busy, agentBusy } = useApp()
  return <section className="panel"><h2>New assessment</h2>
    <div className="mode-tabs" role="tablist" aria-label="Assessment entry mode">
      <button type="button" role="tab" aria-selected={mode === 'letter'} className={`mode-tab${mode === 'letter' ? ' active' : ''}`} onClick={() => setMode('letter')} disabled={busy}>From a letter</button>
      <button type="button" role="tab" aria-selected={mode === 'prompt'} className={`mode-tab${mode === 'prompt' ? ' active' : ''}`} onClick={() => setMode('prompt')} disabled={busy}>Your own prompt</button>
    </div>
    {mode === 'letter'
      ? <form onSubmit={onCreateFromLetter}>
        <label>Target<select required value={assessment.target_id} onChange={e => setAssessment({ ...assessment, target_id: e.target.value })}><option value="">Select target</option>{targets.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label>
        <label>Objective<textarea required value={assessment.objective} onChange={e => setAssessment({ ...assessment, objective: e.target.value })} placeholder="Identify high-risk web vulnerabilities before release" /></label>
        <label>Client requirements<input type="file" accept=".txt,.md,.pdf,.docx" onChange={e => { const file = e.target.files?.[0] || null; e.target.value = ''; setRequirementFile(file) }} /><small>{assessment.requirements ? `Context from “${briefFilename}” is attached and will guide planning.` : 'Optional planning context; every command still needs HITL approval.'}</small></label>
        <button disabled={busy}>{agentBusy('planner') ? 'Drafting the plan…' : brief ? 'Draft plan from the letter' : 'Generate command plan'}</button>
      </form>
      : <form onSubmit={onCreateFromPrompt}>
        <label>Targets{targets.length === 0 ? <small>No targets registered yet — add one in “Add authorized target” above.</small> : <div className="target-pick">{targets.map(t => <button type="button" key={t.id} className={`pick-chip${promptTargetIds.includes(t.id) ? ' picked' : ''}`} onClick={() => togglePromptTarget(t.id)} disabled={busy} aria-pressed={promptTargetIds.includes(t.id)}><b>{t.name}</b><small>{t.scope_domain_ip}</small>{!!t.restricted_tools?.length && <small className="pick-warn">no {t.restricted_tools.join(', ')}</small>}</button>)}</div>}</label>
        <label>Your prompt<textarea required maxLength={1000} value={promptText} onChange={e => setPromptText(e.target.value)} placeholder="Run a deep pre-launch check on the storefront: enumerate services and versions, audit the HTTP security headers, fingerprint the stack, and report anything an attacker could use — stay non-destructive." /><small>{1000 - promptText.length} characters left. With an AI provider configured, your prompt steers the drafted commands; without one, each target gets the standard policy-checked plan.</small></label>
        <button disabled={busy || !promptTargetIds.length || !promptText.trim()}>{agentBusy('planner') ? `Drafting ${promptTargetIds.length || ''} plan${promptTargetIds.length !== 1 ? 's' : ''}…` : `Generate plan${promptTargetIds.length !== 1 ? 's' : ''} from prompt`}</button>
        <small>Pick one or more targets, describe the engagement in your own words, and the framework drafts a plan per target. Scopes, criticality and the letter's per-target tool restrictions still apply, and every command waits for your approval.</small>
      </form>}
  </section>
}
