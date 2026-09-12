import { useApp } from '../lib/AppContext'

// The persisted assessment list: every run survives across sessions until it
// is explicitly removed, and "Clear workspace" is the fresh board between
// two letters or two demos.
export default function AssessmentsPanel({ assessments, targets, selected, onOpen, onDelete, onReset }) {
  const { busy } = useApp()
  return <section className="panel">
    <div className="panel-title"><h2>Assessments</h2><span className="muted">Select a run to inspect</span>{!!(assessments.length || targets.length) && <button className="secondary compact" onClick={onReset} disabled={busy} title="Delete every target, assessment, finding and report — provider and VM settings are kept">Clear workspace</button>}</div>
    <div className="assessment-list">{assessments.length === 0 ? <div className="empty">Create your first authorized assessment.</div> : assessments.map(a => <div key={a.id} className={`assessment-row ${selected?.id === a.id ? 'active' : ''}`}><button className="assessment-open" onClick={() => onOpen(a.id)} disabled={busy}><span><b>#{a.id} · {targets.find(t => t.id === a.target_id)?.name || 'Target'}</b><small>{a.objective}</small></span><span className={`status ${a.status}`}>{a.status.replaceAll('_', ' ')}</span></button><button className="row-delete" title="Delete this assessment" aria-label={`Delete assessment #${a.id}`} onClick={() => onDelete(a.id)} disabled={busy}>×</button></div>)}</div>
  </section>
}
