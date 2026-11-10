import { useApp } from '../lib/AppContext'
import { PHASE_LABEL, PLAN_PHASES, emptyStep } from '../lib/constants'
import CommandCard from './CommandCard'

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
  const lastRecordedIndex = Math.max(-1, ...(selected.executions || []).map(e => e.step_index))

  return <section className="panel">
    <div className="panel-title"><div><span className="eyebrow">ASSESSMENT #{selected.id}</span><h2>{selected.scenario ? 'Scenario command plan' : 'Editable command plan'}</h2></div><button className="secondary compact" onClick={onSave} disabled={busy || !planEditable || !planDirty}>{agentBusy('planner') ? 'Saving…' : 'Save plan'}</button></div>
    <p className="muted intro">Review every command before execution. Enabled steps require approval and pass policy checks.</p>
    {selectedTarget?.scope_type === 'network' && <div className="network-inventory"><b>Discovered hosts</b><span>{selected.discovered_hosts?.length || 0} reported by nmap</span>{selected.discovered_hosts?.length ? <code>{selected.discovered_hosts.join(', ')}</code> : <small>Run the approved discovery steps to populate the inventory. Register any host separately before deeper testing.</small>}</div>}
    {!!selectedTarget?.restricted_tools?.length && <small className="plan-note">Client's letter for this target: {selectedTarget.restricted_tools.join(', ')} {selectedTarget.restricted_tools.length > 1 ? 'are' : 'is'} restricted and will be refused at approval.</small>}
    <div className="plan">{PLAN_PHASES.filter(p => draftPlan.some(step => (step.phase || 'recon') === p)).map(phaseKey => {
      const phaseIdxs = draftPlan.map((step, i) => (step.phase || 'recon') === phaseKey ? i : -1).filter(i => i >= 0)
      const risky = phaseKey === 'exploitation' || phaseKey === 'post_exploitation'
      return <details open={!selected.analyzed_phases?.includes(phaseKey)} key={phaseKey} className={`phase-group${risky ? ' phase-risk' : ''}`}>
        <summary className="phase-head"><b>{PHASE_LABEL(phaseKey)}</b><small>{phaseIdxs.length} step{phaseIdxs.length !== 1 ? 's' : ''}</small></summary>
        {phaseIdxs.map(i => {
          const step = draftPlan[i]
          const execution = executionByStep.get(i)
          const inFlight = runningStep === i
          const execLive = inFlight && liveExec ? liveExec : null
          return <CommandCard key={i} index={i} step={step} execution={execution} live={execLive} elapsed={liveElapsed} assessmentId={selected.id} targetName={selectedTarget?.name || 'Target'} capabilities={capabilities} toolNames={toolNames} busy={busy} planDirty={planDirty} saved={!!selected.plan?.[i]} currentPhase={selected.current_phase || 'recon'} assessmentRunning={selected.status === 'running'} canRemove={!selected.scenario && i > lastRecordedIndex} onPatch={(key, value) => patchStep(i, key, value)} onRemove={() => setDraftPlan(plan => plan.filter((_, n) => n !== i))} onExecute={() => onExecute(i)} scenarioLocked={!!selected.scenario} workflowNode={selected.framework?.nodes?.find(node => node.index === i)} campaignControl={selected.framework_state?.control || 'active'} />
        })}
      </details>
    })}</div>
    <button className="secondary" onClick={() => setDraftPlan(plan => [...plan, { ...emptyStep(capabilities[0]?.tools?.[0]?.name), phase: selected.current_phase || 'recon' }])} disabled={busy || !planEditable || !PLAN_PHASES.includes(selected.current_phase || 'recon')}>Add command</button>
    {draftPlan.length === 0 && <div className="empty">Add at least one command to continue.</div>}
    {planLocked && planEditable && <small className="plan-note">Execution has started. Steps that have already run are frozen — they are the audit record — but you can still add steps for the phase in progress and edit anything that has not run.</small>}
    {!planEditable && <small className="plan-note">{selected.scenario ? 'This plan is fixed to its scenario version. Publish a new version to change the workflow.' : 'Execution has started, so this plan is locked. Failed or abandoned steps can still be re-approved individually.'}</small>}
    {!planLocked && planDirty && <small className="plan-note">Unsaved plan edits. Save the plan so approvals run the commands shown here.</small>}
  </section>
}
