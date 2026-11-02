import { useApp } from '../lib/AppContext'
import { ALLOWED_UPLOAD_SUFFIXES, MAX_UPLOAD_BYTES, fileSuffix } from '../lib/constants'
import Icon from './Icon'

// Two ways into an assessment: from a registered target (the letter import
// path fills objective/requirements for you), or the operator picks targets
// and writes their own engagement prompt.
export default function NewAssessmentPanel({
  targets, briefFilename, brief, mode, setMode,
  assessment, setAssessment, requirementFile, setRequirementFile,
  promptTargetIds, togglePromptTarget, promptText, setPromptText,
  onCreateFromLetter, onCreateFromPrompt, onNavigateTargets,
}) {
  const { busy, agentBusy, setNotice } = useApp()
  const pickRequirements = event => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (!ALLOWED_UPLOAD_SUFFIXES.includes(fileSuffix(file.name))) { setNotice('Use a PDF, Word, Markdown or text file for requirements.'); return }
    if (file.size > MAX_UPLOAD_BYTES) { setNotice('Requirements files must be 5 MB or smaller.'); return }
    setRequirementFile(file)
  }
  return <details className="panel manual-assessment" open={!!assessment.target_id}>
    <summary><Icon name="planner" /><span><b>Create manually</b><small>Use a target and objective, or your own prompt</small></span><Icon name="chevron" /></summary>
    <div className="manual-body">
    <div className="mode-tabs" role="group" aria-label="Assessment entry mode">
      <button type="button" aria-pressed={mode === 'letter'} className={`mode-tab${mode === 'letter' ? ' active' : ''}`} onClick={() => setMode('letter')} disabled={busy}>Target & objective</button>
      <button type="button" aria-pressed={mode === 'prompt'} className={`mode-tab${mode === 'prompt' ? ' active' : ''}`} onClick={() => setMode('prompt')} disabled={busy}>Your prompt</button>
    </div>
    {mode === 'letter'
      ? <form onSubmit={onCreateFromLetter}>
        <label>Target<select required value={assessment.target_id} onChange={e => setAssessment({ ...assessment, target_id: e.target.value })}><option value="">Select target</option>{targets.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label>
        <label>Objective<textarea required maxLength={1000} value={assessment.objective} onChange={e => setAssessment({ ...assessment, objective: e.target.value })} placeholder="Identify high-risk web vulnerabilities before release" /></label>
        <label>Client requirements<input type="file" accept=".txt,.md,.pdf,.docx" onChange={pickRequirements} disabled={busy} /><small>{assessment.requirements ? `Context from “${briefFilename}” is attached.` : 'Optional context. PDF, Word, Markdown or text, up to 5 MB.'}</small></label>
        {requirementFile && <div className="attachment" role="status"><Icon name="reader" /><span>{requirementFile.name}</span><button type="button" className="icon-btn" aria-label="Remove requirements attachment" disabled={busy} onClick={() => setRequirementFile(null)}><Icon name="close" /></button></div>}
        {!targets.length && <p className="muted">Import a letter or <button type="button" className="text-button" onClick={onNavigateTargets}>register a target in Targets</button> to begin.</p>}
        <button disabled={busy || !targets.length}>{agentBusy('planner') ? 'Drafting the plan…' : brief ? 'Draft plan from the letter' : 'Generate command plan'}</button>
      </form>
      : <form onSubmit={onCreateFromPrompt}>
        <div className="target-picker"><span className="field-label">Targets</span>{targets.length === 0 ? <p className="muted">No targets registered yet. <button type="button" className="text-button" onClick={onNavigateTargets}>Open Targets</button> to add one.</p> : <div className="target-pick">{targets.map(t => <button type="button" key={t.id} className={`pick-chip${promptTargetIds.includes(t.id) ? ' picked' : ''}`} onClick={() => togglePromptTarget(t.id)} disabled={busy} aria-pressed={promptTargetIds.includes(t.id)}><b>{t.name}</b><small>{t.scope_domain_ip}</small>{!!t.restricted_tools?.length && <small className="pick-warn">no {t.restricted_tools.join(', ')}</small>}</button>)}</div>}</div>
        <label>Your prompt<textarea required maxLength={1000} value={promptText} onChange={e => setPromptText(e.target.value)} placeholder="Run a deep pre-launch check on the web application: enumerate services and versions, audit the HTTP security headers, fingerprint the stack, and report anything an attacker could use — stay non-destructive." /><small>{1000 - promptText.length} characters left. With an AI provider configured, your prompt steers the drafted commands; without one, each target gets the standard policy-checked plan.</small></label>
        <button disabled={busy || !promptTargetIds.length || !promptText.trim()}>{agentBusy('planner') ? `Drafting ${promptTargetIds.length || ''} plan${promptTargetIds.length !== 1 ? 's' : ''}…` : `Generate plan${promptTargetIds.length !== 1 ? 's' : ''} from prompt`}</button>
        <small>Each target gets its own policy-checked plan. Every command waits for your approval.</small>
      </form>}
    </div>
  </details>
}
