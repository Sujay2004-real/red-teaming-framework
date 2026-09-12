import { useApp } from '../lib/AppContext'
import { PHASE_LABEL, PLAN_PHASES, emptyStep } from '../lib/constants'

// The editable command plan: per-step review, the per-step approval buttons,
// the live terminal for an in-flight command, and the executed-prefix freeze.
// What is actually frozen is the executed prefix, not the plan: an executed
// step is an audit fact and keeps its tool, command and position, while an
// unexecuted step — including one just proposed mid-engagement, or a whole
// phase not yet run — stays editable.
export default function PlanEditor({
  selected, selectedTarget, draftPlan, setDraftPlan, executionByStep,
  runningStep, liveExec, liveElapsed, planLocked, planEditable, planDirty,
  capabilities, toolNames, onSave, onExecute,
}) {
  const { busy, agentBusy } = useApp()
  const patchStep = (i, key, value) => setDraftPlan(plan => plan.map((s, n) => n === i ? { ...s, [key]: value } : s))

  return <section className="panel">
    <div className="panel-title"><div><span className="eyebrow">ASSESSMENT #{selected.id}</span><h2>Editable command plan</h2></div><button className="secondary compact" onClick={onSave} disabled={busy || !planEditable || !planDirty}>{agentBusy('planner') ? 'Saving…' : 'Save plan'}</button></div>
    <p className="muted intro">Review every command before execution. Enabled steps require approval and pass policy checks.</p>
    {selectedTarget?.scope_type === 'network' && <div className="network-inventory"><b>Discovered hosts</b><span>{selected.discovered_hosts?.length || 0} reported by nmap</span>{selected.discovered_hosts?.length ? <code>{selected.discovered_hosts.join(', ')}</code> : <small>Run the approved discovery steps to populate the inventory. Register any host separately before deeper testing.</small>}</div>}
    {!!selectedTarget?.restricted_tools?.length && <small className="plan-note">Client's letter for this target: {selectedTarget.restricted_tools.join(', ')} {selectedTarget.restricted_tools.length > 1 ? 'are' : 'is'} restricted and will be refused at approval.</small>}
    <div className="plan">{PLAN_PHASES.filter(p => draftPlan.some(step => (step.phase || 'recon') === p)).map(phaseKey => {
      const phaseIdxs = draftPlan.map((step, i) => (step.phase || 'recon') === phaseKey ? i : -1).filter(i => i >= 0)
      const risky = phaseKey === 'exploitation' || phaseKey === 'post_exploitation'
      return <div key={phaseKey} className={`phase-group${risky ? ' phase-risk' : ''}`}>
        <div className="phase-head"><b>{PHASE_LABEL(phaseKey)}</b><small>{phaseIdxs.length} step{phaseIdxs.length !== 1 ? 's' : ''}</small></div>
        {phaseIdxs.map(i => {
          const step = draftPlan[i]
          const execution = executionByStep.get(i)
          const running = !!execution && !execution.complete
          const executed = !!execution && execution.complete
          const retryable = !!execution?.retryable
          const savedStep = selected.plan?.[i]
          const locked = running || executed
          const inFlight = runningStep === i
          const execLive = inFlight && liveExec ? liveExec : null
          const label = inFlight ? 'Running…' : running ? 'Running...' : retryable ? 'Re-approve & retry' : executed ? 'Executed' : 'Approve & execute'
          const state = inFlight || running ? 'Execution in progress'
            : executed && execution.return_code === 0 ? `Execution logged${execution.attempt > 1 ? ` (attempt ${execution.attempt})` : ''}`
              : executed ? `Did not succeed (exit ${execution.return_code}) after ${execution.attempt} attempt${execution.attempt > 1 ? 's' : ''}`
                : planDirty ? 'Save the plan before approving'
                  : 'Awaiting explicit approval'
          return <div className={`step ${risky ? 'step-exploit' : ''} ${step.enabled === false ? 'disabled-step' : ''}`} key={i}>
            {execLive && <div className="live-terminal" role="log" aria-live="polite">
              <div className="terminal-bar"><span className="terminal-dot" /><span className="terminal-title">{selectedTarget?.name || 'target'} — live</span><span className="terminal-status">{execLive.running ? `running · ${liveElapsed}s` : 'finishing…'}</span></div>
              <pre className="terminal-body"><span className="terminal-prompt">$ {step.command}</span>{'\n'}{execLive.output || 'connecting…'}{'█'}</pre>
            </div>}
            <div className="step-head"><span className="step-number">{i + 1}</span>
              <select value={step.tool} onChange={e => patchStep(i, 'tool', e.target.value)} disabled={locked}>
                {!toolNames.has(step.tool) && <option value={step.tool}>{step.tool} (not permitted)</option>}
                {capabilities.map(group => <optgroup key={group.id} label={String(group.id).replaceAll('_', ' ')}>{(group.tools || []).map(tool => <option key={tool.name} value={tool.name}>{tool.name}</option>)}</optgroup>)}
              </select>
              <label className="toggle"><input type="checkbox" checked={step.enabled !== false} onChange={e => patchStep(i, 'enabled', e.target.checked)} disabled={locked} /><span /> Enabled</label>
              <button className="icon-btn" title="Remove step" aria-label="Remove step" onClick={() => setDraftPlan(plan => plan.filter((_, n) => n !== i))} disabled={locked}>×</button>
            </div>
            <input className="command" value={step.command} onChange={e => patchStep(i, 'command', e.target.value)} disabled={locked} />
            <input value={step.reason || ''} onChange={e => patchStep(i, 'reason', e.target.value)} placeholder="Why this command is needed" disabled={locked} />
            <div className="step-actions"><span className={executed && execution.return_code === 0 ? 'step-complete' : retryable ? 'step-failed' : ''}>{state}</span>
              {execution?.execution_host && <span className="vm-badge" title={`Ran on the attacker VM ${execution.execution_host.user}@${execution.execution_host.host} · ${execution.execution_host.os} · kernel ${execution.execution_host.kernel} · SSH host key ${execution.execution_host.host_key_fingerprint}`}>ran on Kali VM {execution.execution_host.user}@{execution.execution_host.host}</span>}
              <button disabled={busy || step.enabled === false || running || (executed && !retryable) || planDirty || !savedStep} onClick={() => onExecute(i)}>{label}</button>
            </div>
          </div>
        })}
      </div>
    })}</div>
    <button className="secondary" onClick={() => setDraftPlan(plan => [...plan, emptyStep(capabilities[0]?.tools?.[0]?.name)])} disabled={busy || !planEditable}>Add command</button>
    {draftPlan.length === 0 && <div className="empty">Add at least one command to continue.</div>}
    {planLocked && planEditable && <small className="plan-note">Execution has started. Steps that have already run are frozen — they are the audit record — but you can still add steps for the phase in progress and edit anything that has not run.</small>}
    {!planEditable && <small className="plan-note">Execution has started, so this plan is locked. Failed or abandoned steps can still be re-approved individually.</small>}
    {!planLocked && planDirty && <small className="plan-note">Unsaved plan edits. Save the plan so approvals run the commands shown here.</small>}
  </section>
}
