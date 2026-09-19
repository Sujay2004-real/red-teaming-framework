import { useApp } from '../lib/AppContext'
import { useResource } from '../lib/useResource'
import { fetchProtectedObjectUrl, getOperatorKey } from '../lib/api'

export default function ReportVersions({ assessmentId, status }) {
  const { request, run } = useApp()
  const { data, error } = useResource(request, `/assessments/${assessmentId}/reports`, status)
  const download = version => run('reporter', async () => {
    const url = await fetchProtectedObjectUrl(`/assessments/${assessmentId}/reports/${version.id}`, getOperatorKey)
    const link = document.createElement('a')
    link.href = url; link.download = `assessment-${assessmentId}-v${version.id}.html`; link.click()
    setTimeout(() => URL.revokeObjectURL(url), 10000)
  })
  return <section className="panel"><h2>Report history</h2><p>Each published version retains its evidence hashes and analysis provenance.</p>{error && <p role="alert">{error}</p>}{data?.length === 0 && <div className="empty">Generate a report after analysis to create the first version.</div>}{data?.map(v => <article className="report-version" key={v.id}><div><b>Version {v.id}</b><p>{new Date(v.created_at).toLocaleString()}</p><code>SHA256 {v.digest}</code></div><button className="secondary compact" onClick={() => download(v)}>Download</button></article>)}</section>
}
