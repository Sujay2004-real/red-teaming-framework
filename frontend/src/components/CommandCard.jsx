import { useState } from 'react'
import { useApp } from '../lib/AppContext'
import { useResource } from '../lib/useResource'
import Icon from './Icon'

function RecordedOutput({ assessmentId, execution }) {
  const { request } = useApp()
  const { data, error } = useResource(request, `/assessments/${assessmentId}/executions/${execution.id}/evidence`, execution.attempt)
  if (error) return <p className="inline-error" role="alert">{error}</p>
  if (!data) return <p className="muted" role="status">Loading command evidence…</p>
  return <pre className="terminal-body">{data.stdout || 'No standard output recorded.'}{data.stderr && <span className="terminal-error">{'\n'}{data.stderr}</span>}</pre>
}

export default function CommandCard({ index, step, execution, live, elapsed, assessmentId, targetName,
  capabilities, toolNames, busy, planDirty, saved, currentPhase, assessmentRunning, canRemove, onPatch, onRemove, onExecute }) {
  const { setNotice } = useApp()
  const [outputOpen, setOutputOpen] = useState(false)
  const running = !!execution && !execution.complete
  const executed = !!execution?.complete
  const locked = running || executed
  const retryable = !!execution?.retryable
  const successful = executed && ['completed', 'completed_with_findings'].includes(execution.state)
  const inFlight = !!live || running
  const buttonLabel = inFlight ? 'Running…' : retryable ? 'Re-approve & retry' : successful ? 'Executed' : executed ? 'Failed' : 'Approve & execute'
  const state = inFlight ? 'Execution in progress' : successful ? 'Evidence recorded' : executed ? `Failed · exit ${execution.return_code}` : step.enabled === false ? 'Step disabled' : planDirty ? 'Save the plan before approving' : (step.phase || 'recon') !== currentPhase ? 'Waiting for this phase' : 'Awaiting your approval'
  const copy = async () => {
    try { await navigator.clipboard.writeText(step.command); setNotice('Command copied') }
    catch { setNotice('Copy unavailable; select the command text instead') }
  }
  return <div className={`step command-card${step.enabled === false ? ' disabled-step' : ''}${inFlight ? ' is-running' : successful ? ' is-complete' : executed ? ' is-failed' : ''}`}>
    <div className="command-card-head"><span className="step-number">{index + 1}</span><b>{step.tool || 'New command'}</b><span className={`command-state ${successful ? 'step-complete' : executed ? 'step-failed' : ''}`}>{successful && <Icon name="check" />}{state}</span></div>
    <code className="command-preview">{step.command || 'Add a command in the editor below.'}</code>
    <p className="command-purpose">{step.reason || 'Review this command and confirm it is within the authorized scope.'}</p>
    <div className="command-tags">{step.risk && <span className={`tag risk-${String(step.risk).toLowerCase()}`}>{step.risk} risk</span>}{step.capability && <span className="tag">{String(step.capability).replaceAll('_', ' ')}</span>}{execution?.execution_host && <span className="vm-badge">Ran on Kali · {execution.execution_host.user}@{execution.execution_host.host}</span>}</div>
    <details className="command-edit" open={!step.command}>
      <summary><Icon name="settings" />{locked ? 'Recorded command details' : 'Edit command'}<Icon name="chevron" /></summary>
      <div className="command-edit-body"><div className="step-head">
        <select aria-label={`Tool for step ${index + 1}`} value={step.tool} onChange={e => onPatch('tool', e.target.value)} disabled={locked || busy}>
          {!toolNames.has(step.tool) && <option value={step.tool}>{step.tool} (not permitted)</option>}
          {capabilities.map(group => <optgroup key={group.id} label={String(group.id).replaceAll('_', ' ')}>{(group.tools || []).map(tool => <option key={tool.name} value={tool.name}>{tool.name}</option>)}</optgroup>)}
        </select>
        <label className="toggle"><input type="checkbox" checked={step.enabled !== false} onChange={e => onPatch('enabled', e.target.checked)} disabled={locked || busy} /><span />Enabled</label>
        <button type="button" className="icon-btn" aria-label={`Remove step ${index + 1}`} onClick={onRemove} disabled={busy || !canRemove}><Icon name="close" /></button>
      </div>
      <textarea rows="2" aria-label={`Command for step ${index + 1}`} className="command" value={step.command} onChange={e => onPatch('command', e.target.value.replace(/[\r\n]+/g, ' '))} disabled={locked || busy} />
      <input aria-label={`Reason for step ${index + 1}`} value={step.reason || ''} onChange={e => onPatch('reason', e.target.value)} placeholder="Why this command is needed" disabled={locked || busy} /></div>
    </details>
    {live && <div className="live-terminal" role="region" aria-label="Live command output"><div className="terminal-bar"><span className="terminal-dot" /><span className="terminal-title">{targetName} · live</span><span className="terminal-status">{live.running ? `Running · ${elapsed}s` : 'Finishing…'}</span></div><pre className="terminal-body"><span className="terminal-prompt">$ {step.command}</span>{'\n'}{live.output || 'Waiting for command output…'}</pre></div>}
    {executed && !live && <div className="recorded-output"><button type="button" className="text-button" aria-expanded={outputOpen} onClick={() => setOutputOpen(v => !v)}><Icon name="activity" />{outputOpen ? 'Hide recorded output' : 'Show recorded output'}<Icon name="chevron" /></button>{outputOpen && <RecordedOutput assessmentId={assessmentId} execution={execution} />}</div>}
    <div className="step-actions"><button type="button" className="secondary compact" onClick={copy} disabled={!step.command}>Copy command</button><button type="button" disabled={busy || step.enabled === false || inFlight || (executed && !retryable) || planDirty || !saved || assessmentRunning || !step.command || (step.phase || 'recon') !== currentPhase} onClick={onExecute}>{!executed && !inFlight && <Icon name="shield" />}{buttonLabel}</button></div>
  </div>
}
