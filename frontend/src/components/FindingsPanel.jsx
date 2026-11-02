import { useState } from 'react'
import { useApp } from '../lib/AppContext'
import { useResource } from '../lib/useResource'
import { useDebouncedValue } from '../lib/useDebouncedValue'
import Icon from './Icon'

function FindingDetail({ assessmentId, id, onSaved }) {
  const { request, run, busy } = useApp()
  const { data: finding, error } = useResource(request, `/assessments/${assessmentId}/findings/${id}`)
  if (error) return <p role="alert">{error}</p>
  if (!finding) return <p role="status">Loading evidence...</p>
  const save = event => {
    event.preventDefault()
    const body = Object.fromEntries(new FormData(event.currentTarget))
    body.due_date ||= null
    run('', async () => { await request(`/assessments/${assessmentId}/findings/${id}/review`, { method: 'PUT', body: JSON.stringify(body) }); onSaved() })
  }
  return <div className="finding-detail" aria-busy={busy}><p>{finding.description}</p><h4>Evidence</h4><pre>{finding.evidence || 'No evidence recorded.'}</pre>{finding.exploit_evidence && <><h4>Verification evidence</h4><pre>{finding.exploit_evidence}</pre></>}<h4>Remediation</h4><p>{finding.remediation}</p>
    <form onSubmit={save}><div className="split"><label>Review status<select name="status" defaultValue={finding.review.status}>{['open', 'in_progress', 'resolved', 'accepted_risk', 'reopened'].map(s => <option key={s} value={s}>{s.replaceAll('_', ' ')}</option>)}</select></label><label>Owner<input name="owner" maxLength="150" defaultValue={finding.review.owner} /></label><label>Due date<input type="date" name="due_date" defaultValue={finding.review.due_date} /></label></div><label>Risk acceptance justification<textarea name="justification" maxLength="4000" defaultValue={finding.review.justification} /></label><label>Retest evidence<textarea name="retest_evidence" maxLength="10000" defaultValue={finding.review.retest_evidence} /></label><label>Add comment<textarea name="comment" maxLength="2000" /></label><button className="secondary" disabled={busy}>{busy ? 'Saving…' : 'Save review'}</button></form>
    {finding.review.comments?.map((c, i) => <blockquote key={i}>{c.text}<small>{c.created_at}</small></blockquote>)}
  </div>
}

export default function FindingsPanel({ assessment, assessments }) {
  const { request } = useApp()
  const [filters, setFilters] = useState({ search: '', severity: '', verification: '', tool: '' })
  const [page, setPage] = useState(0), [expanded, setExpanded] = useState(null), [revision, setRevision] = useState(0)
  const [baseline, setBaseline] = useState('')
  const search = useDebouncedValue(filters.search)
  const tool = useDebouncedValue(filters.tool)
  const query = new URLSearchParams({ ...filters, search, tool, offset: page * 30, limit: 30 })
  const { data, error, isLoading } = useResource(request, `/assessments/${assessment.id}/findings?${query}`, revision, { keepPreviousData: true })
  const updating = isLoading || search !== filters.search || tool !== filters.tool
  const { data: comparison, error: comparisonError } = useResource(request, baseline ? `/assessments/${assessment.id}/compare/${baseline}` : '')
  const filter = (key, value) => { setFilters(f => ({ ...f, [key]: value })); setPage(0); setExpanded(null) }
  const levels = ['Critical', 'High', 'Medium', 'Low']
  const hasFilters = Object.values(filters).some(Boolean)
  const resetFilters = () => { setFilters({ search: '', severity: '', verification: '', tool: '' }); setPage(0); setExpanded(null) }
  return <section className="panel findings-panel"><div className="panel-title"><div><span className="eyebrow">EVIDENCE & REMEDIATION</span><h2>Findings that matter</h2></div><span className="tag">{data?.total ?? '…'} matching</span></div>
    <p className="muted">Prioritized observations, with evidence and verification shown for each finding.</p>
    <div className="severity-summary" aria-label="Severity counts for all matching findings">{levels.map(level => <button key={level} type="button" className={`severity-metric ${level}`} aria-pressed={filters.severity === level} aria-label={`Filter ${level} findings`} onClick={() => filter('severity', filters.severity === level ? '' : level)}><span className="severity-dot" /><b>{data?.severity_counts ? data.severity_counts[level] || 0 : '—'}</b><span>{level}</span></button>)}</div>
    <div className="severity-distribution" role="img" aria-label={data?.severity_counts ? levels.map(level => `${level}: ${data.severity_counts[level] || 0}`).join(', ') : 'Severity distribution loading'}>{levels.map(level => <span key={level} className={level} style={{ flexGrow: data?.severity_counts?.[level] || 0 }} />)}</div>
    <div className="distribution-caption"><small>Distribution across all matching findings</small>{hasFilters && <button className="text-button" onClick={resetFilters}>Clear filters</button>}</div>
    <div className="finding-filters"><label>Search<input type="search" maxLength={200} value={filters.search} onChange={e => filter('search', e.target.value)} placeholder="Title or endpoint" /></label><label>Severity<select value={filters.severity} onChange={e => filter('severity', e.target.value)}><option value="">All severities</option>{['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}</select></label><label>Verification<select value={filters.verification} onChange={e => filter('verification', e.target.value)}><option value="">All states</option>{['verified', 'attempted', 'unverified', 'refuted'].map(s => <option key={s}>{s}</option>)}</select></label><label>Tool<input value={filters.tool} onChange={e => filter('tool', e.target.value)} placeholder="e.g. nuclei" /></label></div>
    <div className="results-status" role="status">{error ? 'Findings could not be loaded.' : updating ? (data ? 'Updating results…' : 'Loading findings…') : `${data?.total || 0} matching finding${data?.total === 1 ? '' : 's'}`}</div>
    {error && <div className="inline-error" role="alert"><p>{error}</p><button className="secondary compact" onClick={() => setRevision(v => v + 1)}>Retry findings</button></div>}
    {!data && updating && <div className="findings-placeholder" aria-hidden="true"><span /><span /><span /></div>}
    {!updating && data?.items.length === 0 && <div className="empty"><Icon name="analyst" /><b>{hasFilters ? 'No findings match your filters' : 'No findings yet'}</b><span>{hasFilters ? 'Try a broader search or clear the filters to see all findings.' : assessment.analyzed_phases?.length ? 'Review execution coverage and failures before drawing conclusions.' : 'Findings will appear after you execute and analyze the current phase.'}</span>{hasFilters && <button className="secondary compact" onClick={resetFilters}>Reset filters</button>}</div>}
    <div className="findings">{data?.items.map(f => <article key={f.id}><div><div className="finding-badges"><span className={`severity ${f.severity}`}>{f.severity}</span><span className={`verify-badge ${f.verification || 'unverified'}`}>{f.verification || 'unverified'}</span></div><h3>{f.title}</h3><code>{f.endpoint}</code><p>{f.source_tools?.join(', ')} · {f.review.status.replaceAll('_', ' ')}{f.review.owner && ` · ${f.review.owner}`}</p></div><div className="scores"><span><b>{f.priority_score ?? '—'}</b>Priority</span><span><b>{f.confidence_score != null ? `${f.confidence_score}%` : '—'}</b>Confidence</span></div><button className="secondary compact" aria-expanded={expanded === f.id} onClick={() => setExpanded(expanded === f.id ? null : f.id)}>Evidence and review<Icon name="chevron" /></button>{expanded === f.id && <FindingDetail key={`${f.id}-${revision}`} assessmentId={assessment.id} id={f.id} onSaved={() => setRevision(v => v + 1)} />}</article>)}</div>
    {(page > 0 || data?.total > 30) && <div className="pagination"><button className="secondary" disabled={!page || updating} onClick={() => { setPage(p => p - 1); setExpanded(null) }}>Previous</button><span>Page {page + 1} of {Math.max(1, Math.ceil((data?.total || 0) / 30))}</span><button className="secondary" disabled={updating || !data || (page + 1) * 30 >= data.total} onClick={() => { setPage(p => p + 1); setExpanded(null) }}>Next</button></div>}
    <label>Compare with earlier assessment<select value={baseline} onChange={e => setBaseline(e.target.value)}><option value="">Choose a baseline</option>{assessments.filter(a => a.target_id === assessment.target_id && a.id < assessment.id).map(a => <option key={a.id} value={a.id}>#{a.id} · {a.objective}</option>)}</select></label>
    {baseline && comparisonError && <p role="alert">{comparisonError}</p>}{baseline && comparison && <div><p>{comparison.note}</p>{comparison.items.map(f => <p key={f.fingerprint}><span className="tag">{f.state.replaceAll('_', ' ')}</span> {f.title}</p>)}</div>}
  </section>
}
