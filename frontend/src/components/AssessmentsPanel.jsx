import { useState } from 'react'
import { useApp } from '../lib/AppContext'
import Icon from './Icon'

// The persisted assessment list: every run survives across sessions until it
// is explicitly removed, and "Clear workspace" is the fresh board between
// two letters or two demos.
export default function AssessmentsPanel({ assessments, targets, selected, onOpen, onDelete, onReset }) {
  const { busy } = useApp()
  const [search, setSearch] = useState('')
  const matches = assessments.filter(a => `${a.id} ${a.objective} ${targets.find(t => t.id === a.target_id)?.name || ''} ${a.status.replaceAll('_', ' ')}`.toLowerCase().includes(search.trim().toLowerCase()))
  return <section className="panel">
    <div className="panel-title"><h2>Assessments</h2><Icon name="planner" /></div><p className="muted sidebar-caption">Select an engagement to inspect.</p>
    {assessments.length > 0 && <label className="assessment-search">Find on this page<input type="search" placeholder="Target, objective or status" value={search} onChange={e => setSearch(e.target.value)} /></label>}
    <div className="assessment-list">{assessments.length === 0 ? <div className="empty"><Icon name="planner" /><b>Your first assessment starts here</b><span>Import a letter to create a plan, or use manual setup below.</span></div> : matches.map(a => <div key={a.id} className={`assessment-row ${selected?.id === a.id ? 'active' : ''}`}><button className="assessment-open" aria-current={selected?.id === a.id ? 'true' : undefined} onClick={() => onOpen(a.id)} disabled={busy}><span><b>#{a.id} · {targets.find(t => t.id === a.target_id)?.name || 'Target'}</b><small title={a.objective}>{a.objective}</small></span><span className={`status ${a.status}`}>{a.status.replaceAll('_', ' ')}</span></button><button className="row-delete" title="Delete this assessment" aria-label={`Delete assessment #${a.id}`} onClick={() => onDelete(a.id)} disabled={busy}><Icon name="close" /></button></div>)}</div>
    {!!assessments.length && !matches.length && <div className="empty" role="status"><b>No matching assessments</b><span>Try another target, objective or status.</span><button className="text-button" onClick={() => setSearch('')}>Clear search</button></div>}
    {!!(assessments.length || targets.length) && <details className="assessment-maintenance"><summary>Workspace actions<Icon name="chevron" /></summary><p className="muted">Clearing permanently removes targets, assessments, evidence, and reports. Provider and VM settings are kept.</p><button className="danger compact" onClick={onReset} disabled={busy}>Clear workspace</button></details>}
  </section>
}
