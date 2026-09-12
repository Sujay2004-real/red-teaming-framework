// The execution audit trail: every approved command, its captured output,
// and the attacker-VM attestation when VM mode was active.
export default function AuditTrailPanel({ executions }) {
  if (!executions?.length) return null
  return <section className="panel"><h2>Execution audit trail</h2>
    <div className="audit">{executions.map(e => <details key={e.id}>
      <summary><b>{e.tool_name}</b><code>{e.command}</code><span className={!e.complete ? 'muted' : e.return_code === 0 ? 'ok' : 'fail'}>{e.complete ? `exit ${e.return_code} · ${e.duration_ms} ms` : 'still running'}{e.attempt > 1 ? ` · attempt ${e.attempt}` : ''}</span>{e.execution_host && <span className="vm-badge" title={`${e.execution_host.os} · kernel ${e.execution_host.kernel} · SSH host key ${e.execution_host.host_key_fingerprint}`}>{e.execution_host.user}@{e.execution_host.host}</span>}</summary>
      <pre>{e.stdout || 'No standard output returned.'}</pre>{!!e.stderr && <pre className="stderr">{e.stderr}</pre>}
    </details>)}</div>
  </section>
}
