import { useState } from 'react'
import { useApp } from '../lib/AppContext'
import { useResource } from '../lib/useResource'
import './Framework.css'

export default function WorkflowPanel({ assessment, onChanged, onRetest, onReviewPlan }) {
  const { request, busy } = useApp()
  const [revision, setRevision] = useState(0)
  const version = `${assessment.workflow_revision}-${revision}`
  const path = `/assessments/${assessment.id}`
  const { data, error } = useResource(request, `${path}/framework`, version)
  const { data: history } = useResource(request, `${path}/framework/events?limit=20`, version)
  const baselineId = assessment.framework_state?.baseline_id
  const { data: comparison, error: comparisonError } = useResource(request, baselineId ? `${path}/framework/compare/${baselineId}` : '', version)
  const [working, setWorking] = useState(false)
  const [actionError, setActionError] = useState('')
  const [note, setNote] = useState('')
  const [cleanupNotes, setCleanupNotes] = useState({})
  const [telemetry, setTelemetry] = useState('')
  const act = async (suffix, body) => {
    setWorking(true); setActionError('')
    try {
      const result = await request(`${path}/${suffix}`, { method: 'POST', body: JSON.stringify(body) })
      if (suffix === 'retest') await onRetest(result.id)
      else { setRevision(v => v + 1); await onChanged() }
      return result
    } catch (e) { setActionError(e.message); return null }
    finally { setWorking(false) }
  }
  const importTelemetry = async event => {
    event.preventDefault()
    try {
      const events = JSON.parse(telemetry)
      if (!Array.isArray(events)) throw new Error('Provide a JSON array of telemetry events.')
      if (await act('telemetry', { workflow_revision: data.workflow_revision, events })) setTelemetry('')
    } catch (e) { setActionError(e.message) }
  }
  if (error) return <section className="panel"><h2>Campaign workflow</h2><p role="alert">{error}</p><button onClick={() => setRevision(v => v + 1)}>Retry workflow</button></section>
  if (!data) return <section className="panel"><p role="status">Loading campaign workflow…</p></section>
  const terminal = ['stopped', 'completed'].includes(data.control)
  return <div className="framework-workflow">
    <section className="panel"><div className="panel-title"><div><span className="eyebrow">CAMPAIGN WORKFLOW</span><h2>{data.scenario?.name || 'Engagement controls'}</h2></div><strong>{data.control}</strong></div>
      {data.scenario && <p>Version {data.scenario.version} · {data.nodes.length} steps · <button className="text-button" onClick={onReviewPlan}>Review commands</button></p>}
      <ol className="workflow-nodes">{data.nodes.map(node => <li key={node.id} className={`workflow-node ${node.status}`}><div><b>{node.id}</b><span className="tag">{node.status}</span></div><small>{node.technique}</small><p>{node.reason}</p>{node.depends_on.length > 0 && <small>Requires {node.depends_on.map(dep => `${dep.step}: ${dep.condition}`).join(' · ')}</small>}{node.execution_id && <small>Execution #{node.execution_id}, attempt {node.attempt}</small>}</li>)}</ol>
      {!terminal && <><label>Control note<input maxLength={2000} value={note} onChange={e => setNote(e.target.value)} placeholder="Reason for pausing, stopping, or completing" /></label><div className="framework-actions">
        <button className="secondary" disabled={working || busy || !note.trim()} onClick={() => act('control', { workflow_revision: data.workflow_revision, action: data.control === 'paused' ? 'resume' : 'pause', note })}>{data.control === 'paused' ? 'Resume campaign' : 'Pause and cancel active work'}</button>
        <button className="secondary" disabled={working || busy || !note.trim()} onClick={() => act('control', { workflow_revision: data.workflow_revision, action: 'stop', note })}>Stop campaign</button>
        {data.scenario && <button disabled={working || busy || !note.trim() || !data.can_complete} onClick={() => act('control', { workflow_revision: data.workflow_revision, action: 'complete', note })}>Complete campaign</button>}
      </div><small>Stopping is final for this run. A retest creates a new campaign with fresh evidence.</small></>}
      {data.scenario && <button className="secondary" disabled={working || busy} onClick={() => act('retest', {})}>Create retest campaign</button>}
      {actionError && <p className="inline-error" role="alert">{actionError}</p>}
    </section>
    <section className="panel"><h2>Detection evidence</h2><p>{data.detection.note}</p><p><b>{data.detection.alerted}</b> executions with alerts · <b>{data.detection.evaluated}</b> evaluated of {data.detection.total}</p>
      <div className="framework-table"><table><thead><tr><th>Execution</th><th>Result</th><th>Source</th><th>First alert delay</th></tr></thead><tbody>{data.detection.items.map(item => <tr key={item.execution_id}><td>#{item.execution_id} / attempt {item.attempt}</td><td>{item.status.replaceAll('_', ' ')}</td><td>{item.sources.join(', ') || 'No telemetry'}</td><td>{item.first_alert_delay_seconds == null ? '—' : `${item.first_alert_delay_seconds.toFixed(1)} s`}</td></tr>)}</tbody></table></div>
      {data.control !== 'completed' && <details><summary>Import security telemetry</summary><p>Import up to 100 events from your security tools. Each event needs execution_id, attempt, source, external_id, event_type (alert, observation, or reviewed_no_alert), observed_at with timezone, and summary.</p><form onSubmit={importTelemetry}><label>Telemetry events (JSON array)<textarea rows={8} maxLength={300000} required value={telemetry} onChange={e => setTelemetry(e.target.value)} /></label><button disabled={working || busy || !telemetry.trim()}>Import telemetry</button></form></details>}
    </section>
    {!!data.cleanup.length && <section className="panel"><h2>Cleanup review</h2><p>Review target and scanner artifacts for each executed step. These records are operator attestations tied to an execution attempt.</p>{data.cleanup.map(item => <form className="cleanup-item" key={item.node_id} onSubmit={e => { e.preventDefault(); act('cleanup', { workflow_revision: data.workflow_revision, node_id: item.node_id, note: cleanupNotes[item.node_id] || '' }) }}><h3>{item.node_id} · {item.status.replaceAll('_', ' ')}</h3><p>{item.instruction}</p>{item.record && <p>{item.record.note}</p>}{data.control !== 'completed' && <><label>Cleanup evidence for {item.node_id}<input required maxLength={2000} value={cleanupNotes[item.node_id] || ''} onChange={e => setCleanupNotes(old => ({ ...old, [item.node_id]: e.target.value }))} /></label><button className="secondary" disabled={working || busy || !cleanupNotes[item.node_id]?.trim()}>Record cleanup review</button></>}</form>)}</section>}
    {baselineId && <section className="panel"><h2>Retest comparison · baseline #{baselineId}</h2>{comparisonError && <p>{comparisonError}</p>}{comparison?.items?.map(item => <p key={item.node_id}><b>{item.node_id}</b>: {item.before.objective.replaceAll('_', ' ')} → {item.after.objective.replaceAll('_', ' ')} · executions {item.before.execution} → {item.after.execution}</p>)}</section>}
    {!!history?.items?.length && <section className="panel"><h2>Campaign history</h2><ol className="framework-history">{history.items.map(item => <li key={item.id}><b>{item.kind.replaceAll('_', ' ')}</b><small>{item.actor} · {item.created_at}</small><pre>{JSON.stringify(item.payload, null, 2)}</pre></li>)}</ol><small>Showing the latest {history.items.length} of {history.total} records.</small></section>}
  </div>
}
