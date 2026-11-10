import './ObjectiveEvidence.css'

const STATUS_LABELS = {
  achieved: 'Achieved', pending: 'Pending', inconclusive: 'Inconclusive',
  not_demonstrated: 'Not demonstrated',
}

export default function ObjectiveEvidence({ result }) {
  if (!result?.criteria?.length) return null
  return <section className="panel objective-evidence" aria-label="Campaign objective evidence">
    <div className="objective-heading"><h2>Campaign objective evidence</h2><strong className={`objective-status ${result.status}`}>{STATUS_LABELS[result.status] || 'Inconclusive'}</strong></div>
    <p className="muted">{result.scope_note}</p>
    <div className="objective-list">{result.criteria.map((criterion, index) => <article key={`${criterion.kind}-${index}`}>
      <div className="objective-heading"><h3>{criterion.label}</h3><strong className={`objective-status ${criterion.status}`}>{STATUS_LABELS[criterion.status] || 'Inconclusive'}</strong></div>
      <p><code>{criterion.endpoint}</code> · Parameter: <code>{criterion.parameter}</code></p>
      <p>{criterion.reason}</p>
      {criterion.evidence?.map((proof, proofIndex) => <details key={`${proof.execution_id}-${proofIndex}`}>
        <summary>Execution #{proof.execution_id}, attempt {proof.attempt} · {proof.tool}</summary>
        <pre>{proof.excerpt}</pre>
        <small>Original evidence SHA-256</small><code className="objective-digest">{proof.evidence_sha256 || 'Unavailable'}</code>
      </details>)}
    </article>)}</div>
  </section>
}
