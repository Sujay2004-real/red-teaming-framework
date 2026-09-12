import { useApp } from '../lib/AppContext'
import { PHASE_LABEL, PLAN_PHASES } from '../lib/constants'

// The engagement phase stepper, the next-phase drafting entry point, and the
// adaptive next-step proposals (manual and automatic alike). Proposals are
// never a plan on their own — they only become one when the operator adds
// them to the draft and saves, exactly like a hand-typed step.
export default function PhasePipeline({
  selected, selectedTarget, phases, nextDraftable, currentPhase,
  nextProposals, pickedCandidates, setPickedCandidates, planEditable,
  onDraftPhase, onPropose, onDismissProposals, onAddPicked,
}) {
  const { busy, agentBusy } = useApp()
  return <section className="panel pipeline-panel">
    <div className="panel-title"><h2>Engagement phases</h2><span className="muted">{selected ? `Assessment #${selected.id} · ${PHASE_LABEL(selected.current_phase || 'recon')}` : 'No assessment selected yet'}</span></div>
    <ol className="pipeline phases">
      {phases.map((phase, i) => {
        const active = !phase.done && phases.slice(0, i).every(p => p.done)
        return <li key={phase.key} className={`${phase.done ? 'done' : ''} ${active ? 'active' : ''}${phase.key === 'exploitation' || phase.key === 'post_exploitation' ? ' phase-risk' : ''}`}>
          <span className="stage-dot">{phase.done ? '✓' : i + 1}</span>
          <span className="stage-body"><b>{phase.label}</b><small>{phase.caption}</small></span>
        </li>
      })}
    </ol>
    {selected && nextDraftable && <div className="phase-draft">
      <button onClick={() => onDraftPhase(nextDraftable)} disabled={busy}>{agentBusy('planner') ? 'Drafting…' : `Draft ${PHASE_LABEL(nextDraftable).toLowerCase()} plan`}</button>
      {nextDraftable === 'exploitation' && !selectedTarget?.exploitation_authorized && <small className="gate-note">The letter does not authorize exploitation for this target, so verification steps will be refused — and that refusal is itself required evidence.</small>}
      {nextDraftable === 'exploitation' && selectedTarget?.exploitation_authorized && <small>Steps are drafted from the verified findings: offline exploit lookups, parameter verification, and the letter's proof-of-concept endpoints. Each still waits for your approval.</small>}
      {nextDraftable === 'post_exploitation' && <small>Bounded impact proof only (DBMS banner, current user) — the single verification record per flaw the letter permits.</small>}
    </div>}
    {/* Proposing is available in the phase the assessment is working in,
        because that is the only phase whose new steps can be analyzed as a
        unit. The bookend phases own no steps, so they offer nothing. */}
    {selected && PLAN_PHASES.includes(currentPhase) && <div className="phase-draft proposal-draft">
      <button className="secondary" onClick={onPropose} disabled={busy || selected.status === 'running'}>{agentBusy('planner') ? 'Proposing…' : 'Propose next steps'}</button>
      <small>Ranked from the findings and the audit trail so far, so it answers what to do <em>next</em> rather than restating the checklist. Every candidate is policy-checked before you see it, anything already run is withheld, and each one still needs your approval.</small>
    </div>}
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
