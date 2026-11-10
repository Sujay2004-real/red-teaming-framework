import { useRef, useState } from 'react'
import { useApp } from '../lib/AppContext'
import { useResource } from '../lib/useResource'
import './Framework.css'

export default function ScenarioLibrary({ targets, onCreated }) {
  const { request, busy } = useApp()
  const [revision, setRevision] = useState(0)
  const [offset, setOffset] = useState(0)
  const { data, error } = useResource(request, `/framework/scenarios?offset=${offset}&limit=30`, revision)
  const [chosen, setChosen] = useState(null)
  const [targetId, setTargetId] = useState('')
  const [bindings, setBindings] = useState({})
  const [preview, setPreview] = useState(null)
  const [working, setWorking] = useState(false)
  const [message, setMessage] = useState('')
  const [document, setDocument] = useState('')
  const generation = useRef(0)
  const change = action => { generation.current++; setPreview(null); setMessage(''); action() }
  const select = item => change(() => {
    setChosen(item)
    setBindings(Object.fromEntries(Object.entries(item.inputs).map(([key, spec]) => [key, spec.default || ''])))
  })
  const payload = () => ({ scenario_id: chosen.id, version: chosen.version, target_id: Number(targetId), bindings })
  const inspect = async event => {
    event.preventDefault()
    const current = ++generation.current
    setWorking(true); setMessage(''); setPreview(null)
    try {
      const result = await request('/framework/preview', { method: 'POST', body: JSON.stringify(payload()) })
      if (current === generation.current) setPreview(result)
    } catch (e) { if (current === generation.current) setMessage(e.message) }
    finally { setWorking(false) }
  }
  const create = async () => {
    setWorking(true); setMessage('')
    try {
      const result = await request('/framework/assessments', { method: 'POST', body: JSON.stringify(payload()) })
      await onCreated(result.id)
    } catch (e) { setMessage(e.message) }
    finally { setWorking(false) }
  }
  const publish = async event => {
    event.preventDefault(); setWorking(true); setMessage('')
    try {
      const parsed = JSON.parse(document)
      await request('/framework/scenarios', { method: 'POST', body: JSON.stringify(parsed) })
      setDocument(''); setRevision(v => v + 1); setMessage('Scenario version added to the library.')
    } catch (e) { setMessage(e.message) }
    finally { setWorking(false) }
  }
  const exportDocument = async () => {
    setWorking(true); setMessage('')
    try {
      const definition = await request(`/framework/scenarios/${chosen.id}/${chosen.version}`)
      setDocument(JSON.stringify(definition, null, 2))
      setMessage('Scenario definition opened below. Choose a new name or version before publishing changes.')
    } catch (e) { setMessage(e.message) }
    finally { setWorking(false) }
  }
  return <div className="framework-library">
    <section className="panel"><span className="eyebrow">REUSABLE CAMPAIGNS</span><h2>Scenario library</h2>
      <p className="muted">Choose a workflow, bind an authorized target, and review its commands. Each execution requires your approval.</p>
      {error && <p role="alert">{error}<button onClick={() => setRevision(v => v + 1)}>Retry library</button></p>}
      {!data && !error && <p role="status">Loading scenarios…</p>}
      <div className="scenario-grid">{data?.items?.map(item => <button type="button" key={`${item.id}@${item.version}`}
        className={`scenario-choice secondary${chosen?.id === item.id && chosen?.version === item.version ? ' selected' : ''}`}
        aria-pressed={chosen?.id === item.id && chosen?.version === item.version} disabled={working || busy} onClick={() => select(item)}>
        <b>{item.name}</b><span>{item.description}</span><small>Version {item.version} · {item.steps.length} steps</small>
      </button>)}</div>
      {!!data && data.total > 30 && <div className="framework-actions"><button disabled={offset === 0} onClick={() => setOffset(v => Math.max(0, v - 30))}>Previous</button><button disabled={offset + 30 >= data.total} onClick={() => setOffset(v => v + 30)}>Next</button></div>}
    </section>
    {chosen && <section className="panel"><h2>{chosen.name}</h2>
      <form onSubmit={inspect} className="framework-form">
        <label>Authorized target<select required value={targetId} disabled={working || busy} onChange={e => change(() => setTargetId(e.target.value))}><option value="">Select target</option>{targets.map(target => <option key={target.id} value={target.id}>{target.name} — {target.scope_domain_ip}</option>)}</select></label>
        {Object.entries(chosen.inputs).map(([key, spec]) => <label key={key}>{spec.label}<input required maxLength={1000} value={bindings[key] || ''} disabled={working || busy} onChange={e => change(() => setBindings(old => ({ ...old, [key]: e.target.value })))} placeholder={spec.type === 'url' ? 'https://application.example' : spec.type === 'ports' ? '80,443' : ''} /></label>)}
        <button disabled={working || busy || !targets.length}>{working ? 'Checking…' : 'Review scenario plan'}</button>
      </form>
      {preview && <div className="scenario-preview"><h3>Commands for review</h3>{preview.tools && <p>Execution tools: {Object.entries(preview.tools).map(([tool, status]) => `${tool}: ${status.replaceAll('_', ' ')}`).join(' · ')}</p>}<ol>{preview.plan.map(step => <li key={step.scenario_node}><b>{step.scenario_node}</b><code>{step.command}</code><p>{step.reason}</p><small>{step.phase.replaceAll('_', ' ')}{step.attack_techniques?.length ? ` · ATT&CK ${step.attack_techniques.join(', ')}` : ''}</small></li>)}</ol><button disabled={working || busy} onClick={create}>Create campaign</button></div>}
      <button className="secondary" disabled={working || busy} onClick={exportDocument}>Open reusable definition</button>
    </section>}
    {message && <p className="notice" role="status">{message}</p>}
    <details className="panel" open={!!document}><summary>Import or edit a scenario definition</summary><p>Publish a new version to preserve existing campaign records. Definitions compose techniques from the installed library.</p><form onSubmit={publish}><label>Scenario JSON<textarea rows={12} maxLength={60000} required value={document} onChange={e => setDocument(e.target.value)} /></label><button disabled={working || busy || !document.trim()}>Publish scenario version</button></form></details>
  </div>
}
