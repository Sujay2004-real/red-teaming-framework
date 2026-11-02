import { useApp } from '../lib/AppContext'
import { PHASE_LABEL, PLAN_PHASES } from '../lib/constants'
import Icon from './Icon'

// The engagement phase stepper, the next-phase drafting entry point, and the
// adaptive next-step proposals (manual and automatic alike). Proposals are
// never a plan on their own — they only become one when the operator adds
// them to the draft and saves, exactly like a hand-typed step.
export default function PhasePipeline({
  selected, selectedTarget, phases, nextDraftable, currentPhase,
  nextProposals, pickedCandidates, setPickedCandidates, planEditable,
  onDraftPhase, onPropose, onDismissProposals, onAddPicked,
  canAnalyze, canReport, planDirty, running, onReviewPlan, onAnalyze, onReport,
}) {
  const { busy, agentBusy } = useApp()
  const completed = phases.filter(p => p.done).length
  const activeKey = phases.find(p => p.key === currentPhase && !p.done && !p.blocked)?.key || phases.find(p => !p.done && !p.blocked)?.key
  const restricted = nextDraftable === 'exploitation' && !selectedTarget?.exploitation_authorized
  let next = { title: 'Review your command plan', description: 'Check the purpose and scope of each command, then approve one step at a time.', label: 'Review command plan', action: onReviewPlan, icon: 'shield' }
  if (running) next = { title: 'A command is running', description: 'Follow its live output. Evidence is recorded as the command completes.', label: 'View live output', action: onReviewPlan, icon: 'activity' }
  else if (planDirty) next = { title: 'Your plan has unsaved changes', description: 'Review and save the draft before approving another command.', label: 'Review plan changes', action: onReviewPlan, icon: 'planner' }
  else if (nextDraftable && !restricted) next = { title: `Continue to ${PHASE_LABEL(nextDraftable).toLowerCase()}`, description: 'Draft the next phase from the recorded findings. Each new command still requires your approval.', label: agentBusy('planner') ? 'Drafting…' : 'Draft next phase', action: () => onDraftPhase(nextDraftable), icon: 'planner' }
  else if (canAnalyze) next = { title: 'Your phase is ready for analysis', description: 'Correlate the recorded outputs, score findings, and review any execution failures.', label: agentBusy('analyst') ? 'Analyzing…' : 'Analyze results', action: onAnalyze, icon: 'analyst' }
  else if (canReport) next = { title: selected?.status === 'reported' ? 'Your report is ready' : 'Prepare your client report', description: 'Review the findings, evidence, and analysis provenance before delivery.', label: 'Open reporting', action: onReport, icon: 'reporter' }
  return <section className="panel pipeline-panel">
    <div className="panel-title"><div><span className="eyebrow">ENGAGEMENT WORKFLOW</span><h2>From scope to evidence</h2></div><span className="tag">{completed} / {phases.length} phases complete</span></div>
    {selected && <div className={`next-action${restricted ? ' restricted' : ''}`}>
      <span className="section-icon"><Icon name={next.icon} /></span><div><span className="eyebrow">NEXT ACTION</span><h3>{next.title}</h3><p>{next.description}</p></div><button onClick={next.action} disabled={busy}>{next.label}<Icon name="arrow" /></button>
    </div>}
    <ol className="pipeline phases">
      {phases.map((phase, i) => {
        const active = !phase.done && !phase.blocked && phase.key === activeKey
        return <li key={phase.key} aria-current={active ? 'step' : undefined} className={`${phase.done ? 'done' : ''} ${active ? 'current' : ''} ${phase.blocked && !phase.done ? 'blocked' : ''}`}>
          <span className="stage-dot">{phase.done ? <Icon name="check" /> : phase.blocked ? <Icon name="lock" /> : i + 1}</span>
          <span className="stage-body"><b>{phase.label}</b><span className="stage-label">{phase.done ? 'Completed' : phase.blocked ? 'Not authorized' : active ? 'Current phase' : 'Upcoming'}</span><small>{phase.caption}</small></span>
        </li>
      })}
    </ol>
    {/* Proposing is available in the phase the assessment is working in,
        because that is the only phase whose new steps can be analyzed as a
        unit. The bookend phases own no steps, so they offer nothing. */}
    {selected && PLAN_PHASES.includes(currentPhase) && <details className="proposal-options"><summary>Explore adaptive next steps<Icon name="chevron" /></summary><div className="phase-draft proposal-draft">
      <button className="secondary" onClick={onPropose} disabled={busy || selected.status === 'running'}>{agentBusy('planner') ? 'Proposing…' : 'Propose next steps'}</button>
      <small>Proposals use the recorded findings and audit trail. Each candidate is policy-checked and requires approval.</small>
    </div></details>}
    {nextProposals && <div className="proposals">
      <div className="proposal-head">
        <div><b>Proposed next steps</b>{nextProposals.origin === 'auto' && <span className="tag good auto-tag">automatic</span>}<small>{nextProposals.candidates.length} for {PHASE_LABEL(nextProposals.phase).toLowerCase()} · {String(nextProposals.source).replaceAll('-', ' ')} · from {nextProposals.state.findings} finding{nextProposals.state.findings !== 1 ? 's' : ''} and {nextProposals.state.executed_steps} recorded step{nextProposals.state.executed_steps !== 1 ? 's' : ''}</small></div>
        <button className="secondary compact" onClick={onDismissProposals} disabled={busy}>Dismiss</button>
      </div>
      {nextProposals.candidates.map((candidate, index) => <label key={`${index}-${candidate.command}`} className={`proposal ${pickedCandidates.has(index) ? 'picked' : ''}`}>
        <input type="checkbox" checked={pickedCandidates.has(index)} onChange={e => setPickedCandidates(current => { const next = new Set(current); if (e.target.checked) next.add(index); else next.delete(index); return next })} disabled={busy} />
        <span className="proposal-body">
          <code>{candidate.command}</code>
          <small>{candidate.reason}</small>
          <span className="proposal-tags">
            <span className="tag">{candidate.tool}</span>
            <span className="tag">{String(candidate.capability).replaceAll('_', ' ')} · {candidate.risk} risk</span>
            {/* Provenance: which finding drove this. A model naming a
                finding that does not exist has it dropped server-side,
                so every chip here points at something real. */}
            {candidate.driven_by.map(item => <span key={item.id} className={`tag driver ${item.severity}`} title={item.title}>from finding #{item.id} · {item.severity}</span>)}
            {candidate.confidence < 100 && <span className="tag muted-tag">{candidate.confidence}% confidence</span>}
          </span>
        </span>
      </label>)}
      {!nextProposals.candidates.length && <div className="empty">Nothing further can be proposed for this phase from the current state.</div>}
      <div className="proposal-actions">
        <button onClick={onAddPicked} disabled={busy || !pickedCandidates.size || !planEditable}>Add {pickedCandidates.size || ''} to the plan</button>
        <small>Adds them to the draft plan as ordinary steps — edit them freely, then Save plan. Each still needs its own approval to run.</small>
      </div>
      {/* The refusals are part of the answer, not an error to hide: they
          are the policy engine's receipt for a model that proposed
          something impermissible. */}
      {!!nextProposals.refused.length && <details className="refused"><summary>{nextProposals.refused.length} proposal{nextProposals.refused.length !== 1 ? 's' : ''} refused by the policy engine</summary><ul>{nextProposals.refused.map((item, index) => <li key={index}><code>{item.command}</code><span>{item.reason}</span></li>)}</ul></details>}
      {!!nextProposals.notes.length && <ul className="proposal-notes">{nextProposals.notes.map((note, index) => <li key={index}>{note}</li>)}</ul>}
    </div>}
  </section>
}
