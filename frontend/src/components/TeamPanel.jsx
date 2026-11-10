import { useState } from 'react'
import { useApp } from '../lib/AppContext'
import { useResource } from '../lib/useResource'

export default function TeamPanel() {
  const { request } = useApp()
  const [revision, setRevision] = useState(0)
  const { data: principal } = useResource(request, '/team/me')
  const { data, error } = useResource(request, principal?.role === 'admin' ? '/team/credentials' : '', revision)
  const { data: workers } = useResource(request, '/framework/workers', revision)
  const [name, setName] = useState('')
  const [role, setRole] = useState('operator')
  const [key, setKey] = useState('')
  const [message, setMessage] = useState('')
  const [working, setWorking] = useState(false)
  const act = async (path, options) => {
    setWorking(true); setMessage(''); setKey('')
    try {
      const result = await request(path, options)
      if (result.key) { setKey(result.key); setName('') }
      setRevision(v => v + 1)
    } catch (e) { setMessage(e.message) }
    finally { setWorking(false) }
  }
  return <>
    <section className="panel"><h2>Team access</h2><p>{principal ? `Signed in as ${principal.name} · ${principal.role}` : 'Loading access…'}</p>
      <p>Named credentials share this workspace. Viewers can inspect reports and redacted evidence. Operators can manage assessments. Administrators also manage settings, credentials, and original-evidence access.</p>
      {(error || message) && <p role="alert">{error || message}</p>}
      {principal?.role === 'admin' && <><form className="framework-form" onSubmit={e => { e.preventDefault(); act('/team/credentials', { method: 'POST', body: JSON.stringify({ name, role }) }) }}>
        <label>Credential name<input maxLength={80} required value={name} onChange={e => setName(e.target.value)} /></label>
        <label>Role<select value={role} onChange={e => setRole(e.target.value)}><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Administrator</option></select></label>
        <button disabled={working || !name.trim()}>Create credential</button>
      </form>{key && <div className="notice"><p>Copy this key now. It will not be displayed again.</p><code style={{ overflowWrap: 'anywhere' }}>{key}</code><button className="secondary" onClick={() => setKey('')}>Hide key</button></div>}
      <ul>{data?.items?.map(item => <li key={item.id}>{item.name} · {item.role} · {item.active ? 'active' : 'revoked'} {item.active && item.name !== principal.name && <button className="text-button" disabled={working} onClick={() => act(`/team/credentials/${item.id}`, { method: 'DELETE' })}>Revoke {item.name}</button>}</li>)}</ul></>}
    </section>
    <section className="panel"><h2>Execution workers</h2><p>Workers report tools installed in their local execution environment. Use the connection check above for tools on the configured Kali VM.</p><button className="secondary" onClick={() => setRevision(v => v + 1)}>Refresh workers</button>{workers?.items?.length ? workers.items.map(item => <article key={item.id}><h3>{item.hostname} · {item.online ? 'online' : 'offline'}</h3><p>{item.active_jobs} active jobs · {item.local_tools.join(', ') || 'No local scanner tools detected'}</p><small>Last heartbeat: {item.heartbeat_at}</small></article>) : <p>No worker heartbeat recorded.</p>}</section>
  </>
}
