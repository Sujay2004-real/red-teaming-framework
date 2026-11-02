import { useRef } from 'react'
import { useApp } from '../lib/AppContext'
import { ALLOWED_UPLOAD_SUFFIXES, MAX_UPLOAD_BYTES, fileSuffix } from '../lib/constants'
import Icon from './Icon'

// The engagement letter: the dropzone reads it, the parsed brief shows what
// the agent was asked to do, and one click registers every target and drafts
// a plan for each. Everything downstream (scopes, tool restrictions,
// exploitation authorization) is derived from this document.
export default function LetterPanel({
  brief, briefFilename, targets, onClear, onImport, onRegisterTarget, onSetup, collapsed = false, rules,
}) {
  const { busy, agentBusy, setNotice } = useApp()
  const briefFileRef = useRef(null)

  // Validation runs before any request so a bad pick — wrong type, too
  // large, or a dropped folder, which arrives as no file at all — gets a
  // plain sentence instead of silence or a raw 4xx from the server.
  const pickFile = file => {
    if (!file) { setNotice('No file was selected. Click anywhere in the box to browse, or drop the letter onto it.'); return }
    if (!ALLOWED_UPLOAD_SUFFIXES.includes(fileSuffix(file.name))) { setNotice(`“${file.name}” is not a supported format. Use PDF, Word, Markdown or text.`); return }
    if (file.size > MAX_UPLOAD_BYTES) { setNotice(`“${file.name}” is larger than 5 MB, the maximum the reader accepts.`); return }
    onImport(file)
  }

  return <details className="panel brief-panel" open={!collapsed}>
    <summary className="brief-summary"><span className="section-icon"><Icon name="reader" /></span><span><span className="eyebrow">{collapsed ? 'SCOPE & AUTHORIZATION' : 'START HERE'}</span><b>{brief ? 'Engagement letter' : 'Import engagement letter'}</b>{brief && <small>{briefFilename}</small>}</span><span className={`tag ${brief ? 'good' : ''}`}>{brief ? 'Imported' : 'PDF · DOCX · TXT'}</span><Icon name="chevron" /></summary>
    <div className="brief-body">
    {/* The whole box is the picker: clicks and Enter/Space forward to
        the hidden input, which clears itself after every pick so
        re-choosing the same file still fires onChange. */}
    {!brief ? <div className={`dropzone${agentBusy('reader') ? ' reading' : ''}`} role="button" tabIndex={busy ? -1 : 0} aria-disabled={busy} aria-busy={agentBusy('reader')} aria-label="Import the client engagement letter"
      onClick={() => { if (!busy) briefFileRef.current?.click() }}
      onKeyDown={e => { if (!busy && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); briefFileRef.current?.click() } }}
      onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); if (!busy) pickFile(e.dataTransfer.files?.[0]) }}>
      <span className="upload-mark"><Icon name={agentBusy('reader') ? 'reader' : 'upload'} /></span>
      <span className="drop-pick">{agentBusy('reader') ? 'Reading your engagement letter…' : 'Drop your engagement letter here'}</span>
      <input id="brief-file" type="file" accept=".txt,.md,.pdf,.docx" hidden ref={briefFileRef}
        onChange={e => { const file = e.target.files?.[0] || null; e.target.value = ''; pickFile(file) }} />
      <small>{agentBusy('reader') ? 'Extracting the scope, targets, and rules of engagement.' : 'Or click to browse. PDF, Word, Markdown or text, up to 5 MB.'}</small>
      <span className="drop-caption">Scope and rules are reviewed before any command runs.</span>
    </div> : <>
      <div className="brief-toolbar"><p className="brief-meta"><b>{brief.client_name || 'Client'}</b>{brief.engagement_ref && <> · <code>{brief.engagement_ref}</code></>}{brief.test_window && <> · test window {brief.test_window}</>}</p><button className="secondary compact" onClick={onClear} disabled={busy}>Clear letter</button></div>
      <div className="brief-targets">
        {brief.targets.map((t, i) => {
          const registered = targets.some(existing => existing.scope_domain_ip === t.address)
          return <div className="brief-target" key={i}>
            <div className="brief-target-head">
              <div><b>{t.name || t.address}</b><small>{t.address}{t.technology ? ` · ${t.technology}` : ''}</small></div>
              <div className="criticality"><span style={{ '--level': (Number.isFinite(t.criticality) ? t.criticality : 70) }}><b>{Number.isFinite(t.criticality) ? t.criticality : '—'}</b></span><small>criticality</small></div>
            </div>
            <div className="chip-row">
              {(t.scopes || []).map(s => <span className="chip" key={s}>{s}</span>)}
              {!!t.restricted_tools?.length && <span className="chip warn" title="The client's letter rules these tools out for this target">no {t.restricted_tools.join(', ')}</span>}
              {t.assessment_type && <span className="chip">{t.assessment_type}</span>}
              {t.exploitation_authorized && <span className="chip good" title="The letter authorizes controlled vulnerability verification (bounded proof-of-concept) against this target">controlled verification authorized</span>}
            </div>
            {registered
              ? <span className="registered-note">Registered ✓</span>
              : <button className="compact" onClick={() => onRegisterTarget(t)} disabled={busy}>{agentBusy('registrar') ? 'Registering…' : 'Register this target'}</button>}
          </div>
        })}
      </div>
      {rules && <details className="brief-details rules-review"><summary>Review enforceable engagement rules</summary>{rules}</details>}
      <div className="brief-actions">
        <button onClick={onSetup} disabled={busy}>{agentBusy('registrar') || agentBusy('planner') ? 'Setting up…' : 'Set up everything from this letter'}</button>
        <small>Registers the targets and drafts a plan for each. Every command still requires your approval.</small>
      </div>
      {!!brief.objectives?.length && <details className="brief-details" open><summary>What the client asked for ({brief.objectives.length})</summary><ol>{brief.objectives.map((o, i) => <li key={i}>{o}</li>)}</ol></details>}
      {(!!brief.out_of_scope?.length || !!brief.prohibited?.length) && <details className="brief-details"><summary>Out of scope ({brief.out_of_scope?.length || 0}) & prohibited techniques ({brief.prohibited?.length || 0})</summary>
        {!!brief.out_of_scope?.length && <><b>Never touch</b><ul>{brief.out_of_scope.map((o, i) => <li key={i}>{o}</li>)}</ul></>}
        {!!brief.prohibited?.length && <><b>Never do</b><ul>{brief.prohibited.map((p, i) => <li key={i}>{p}</li>)}</ul></>}
      </details>}
    </>}
    </div>
  </details>
}
