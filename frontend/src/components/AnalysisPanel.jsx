import { useApp } from '../lib/AppContext'
import { PHASE_LABEL } from '../lib/constants'

// Analysis & report actions. Analysis is gated on the current phase's saved
// steps only; the report cites the engagement brief and every command. The
// report link goes through a key-authenticated blob fetch - a plain <a href>
// cannot carry the operator key header the download now requires.
export default function AnalysisPanel({ selected, currentPhase, phaseSteps, phaseCompleted, planDirty, canAnalyze, canReport, reportUrl, onAnalyze, onReport, onDownloadReport }) {
  const { busy, agentBusy } = useApp()
  return <section className="panel action-panel">
    <div>
      <h2>Analysis &amp; report</h2>
      <p>Correlates outputs, removes duplicate findings, and calculates transparent risk and priority scores.</p>
      <span className="action-status">{canAnalyze ? `All enabled ${PHASE_LABEL(currentPhase).toLowerCase()} steps complete` : `${phaseCompleted.length}/${phaseSteps.length || 0} ${PHASE_LABEL(currentPhase).toLowerCase()} steps complete${planDirty ? ' · unsaved plan edits' : ''}`}</span>
      {selected.analysis_mode && <span className="analysis-mode">Analyzed with: {selected.analysis_mode === 'ai-provider' ? 'AI provider' : 'deterministic local analyzer'}</span>}
    </div>
    <div>
      <button className="secondary" onClick={onAnalyze} disabled={busy || !canAnalyze}>{agentBusy('analyst') ? 'Analyzing…' : 'Analyze results'}</button>
      <button onClick={onReport} disabled={busy || !canReport}>{agentBusy('reporter') ? 'Writing the report…' : 'Generate report'}</button>
      {reportUrl && <a className="download-link report-fallback" href={reportUrl} target="_blank" rel="noreferrer">Your browser blocked the report tab — open it here</a>}
      {selected.status === 'reported' && <button type="button" className="download-link" onClick={onDownloadReport}>Download last report</button>}
    </div>
  </section>
}
