import { useState } from 'react'
import { useApp } from '../lib/AppContext'
import { useResource } from '../lib/useResource'

function Evidence({ assessmentId, execution }) {
  const { request } = useApp()
  const prefix = `/assessments/${assessmentId}/executions/${execution.id}`
  const { data, error } = useResource(request, prefix + '/evidence', execution.attempt)
  const { data: attempts } = useResource(request, prefix + '/attempts', execution.attempt)
  return <>{error && <p role="alert">{error}</p>}<pre>{data?.stdout || 'No standard output recorded.'}</pre>{data?.stderr && <pre className="stderr">{data.stderr}</pre>}{attempts?.map(a => <details key={a.attempt}><summary>Attempt {a.attempt} ? {a.state} ? {a.duration_ms} ms</summary><pre>{a.stdout}</pre><pre>{a.stderr}</pre></details>)}</>
}

export default function AuditTrailPanel({ assessmentId, executions }) {
  const [expanded, setExpanded] = useState(null)
  return <section className="panel"><h2>Execution audit trail</h2>{!executions?.length && <div className="empty">Approved commands and their attempts will appear here.</div>}<div className="audit">{executions?.map(e => <article key={e.id}><button className="audit-summary secondary" aria-expanded={expanded === e.id} onClick={() => setExpanded(expanded === e.id ? null : e.id)}><b>{e.tool_name}</b><code>{e.command}</code><span>{e.state.replaceAll('_', ' ')} ? attempt {e.attempt} ? {e.duration_ms} ms</span></button>{expanded === e.id && <Evidence assessmentId={assessmentId} execution={e} />}</article>)}</div></section>
}
