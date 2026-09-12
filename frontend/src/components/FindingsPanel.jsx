// The correlated, scored findings for the assessment in view, with the
// exploitation verification state each finding carries.
export default function FindingsPanel({ findings }) {
  if (!findings?.length) return null
  return <section className="panel">
    <div className="panel-title"><h2>Prioritized findings</h2><span className="tag good">{findings.length} correlated</span></div>
    <div className="findings">{findings.map(f => <article key={f.id} className={f.verification === 'verified' ? 'finding-verified' : ''}>
      <div>
        <span className={`severity ${f.severity}`}>{f.severity}</span>
        {f.verification === 'verified' && <span className="verify-badge verified" title={`Proven by controlled exploitation: ${f.verified_by?.join(', ')}`}>✓ verified by exploitation</span>}
        {f.verification === 'attempted' && <span className="verify-badge attempted" title="An exploitation step ran against this finding but produced no confirming output">exploitation attempted</span>}
        <h3>{f.title}</h3>
        {(f.endpoint || f.parameter) && <div className="finding-loc">{f.endpoint}{f.parameter ? ` · param: ${f.parameter}` : ''}</div>}
        <p>{f.description}</p>
        <div className="score-chips"><span>Exploit {f.exploitability || 3}/5</span><span>Impact {f.impact || 3}/5</span><span>Exposure {f.exposure || 3}/5</span></div>
        {!!f.source_tools?.length && <small>Reported by {f.source_tools.join(', ')}</small>}
      </div>
      <div className="scores"><span><b>{f.priority_score}</b>Priority</span><span><b>{f.risk_score}</b>Risk / 125</span><span><b>{f.confidence_score}%</b>Confidence</span></div>
      <details><summary>Evidence and remediation</summary><pre>{f.evidence}</pre>{!!f.exploit_evidence && <><b className="exploit-proof-title">Exploitation proof</b><pre className="exploit-proof">{f.exploit_evidence}</pre></>}<p><b>Fix:</b> {f.remediation}</p></details>
    </article>)}</div>
  </section>
}
