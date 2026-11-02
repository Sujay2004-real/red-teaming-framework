import { useState } from 'react'
import { useApp } from '../lib/AppContext'
import { useResource } from '../lib/useResource'

// The post-compromise campaign surface: the footholds, recovered loot and
// discovered hosts the kill chain is built on, plus the opt-in autopilot loop.
//
// Everything here is evidence-derived. The panel never invents a host or a
// credential, and it never runs a command: the autopilot proposes and drafts,
// every drafted step still lands in the ordinary plan and needs its own human
// approval, and reading a recovered secret is a separate, audited action.
export default function CampaignPanel({ assessmentId, aggressive, onChanged }) {
  const { request, pushFeed, busy, setNotice } = useApp()
  const [revision, setRevision] = useState(0)
  const [working, setWorking] = useState('')
  const [revealed, setRevealed] = useState({})
  const [actionError, setActionError] = useState('')
  const { data: campaign, error } = useResource(request, `/assessments/${assessmentId}/campaign`, revision, { keepPreviousData: true })

  const act = async (label, path, options) => {
    setWorking(label)
    setActionError('')
    try {
      const result = await request(path, options)
      setRevision(value => value + 1)
      if (onChanged) await onChanged()
      return result
    } catch (e) {
      setActionError(e.message)
      pushFeed(e.message, 'error')
      return null
    } finally {
      setWorking('')
    }
  }

  const setAutopilot = async enabled => {
    const result = await act('autopilot', `/assessments/${assessmentId}/autopilot`,
      { method: 'POST', body: JSON.stringify({ enabled }) })
    if (result) pushFeed(enabled ? 'Autopilot enabled: it will draft and propose the next kill-chain phase, never run it.' : 'Autopilot disabled.', 'ok')
  }

  const runIteration = async () => {
    const result = await act('run', `/assessments/${assessmentId}/autopilot/run`, { method: 'POST' })
    if (result) {
      const message = result.next_action || result.stopped || 'Autopilot ran one iteration.'
      pushFeed(message, result.stopped ? 'warn' : 'ok')
      setNotice(message)
    }
  }

  const reveal = async loot => {
    const result = await act(`reveal-${loot.id}`, `/assessments/${assessmentId}/loot/${loot.id}/reveal`)
    if (result) {
      setRevealed(current => ({ ...current, [loot.id]: result.secret }))
      pushFeed(`Revealed the recovered secret for ${loot.username || 'unknown'} on ${loot.host}. The access is logged.`, 'warn')
    }
  }

  const promote = async host => {
    const result = await act(`promote-${host.id}`, `/assessments/${assessmentId}/promote/${host.id}`, { method: 'POST' })
    if (result) pushFeed(`Promoted ${host.address} into child assessment #${result.child_assessment_id}, scoped to that host alone.`, 'ok')
  }

  const hide = id => setRevealed(current => { const next = { ...current }; delete next[id]; return next })

  if (error) return <section className="panel"><h2>Campaign</h2><p role="alert">{error}</p><button className="secondary" onClick={() => setRevision(v => v + 1)}>Retry campaign</button></section>
  if (!campaign) return <section className="panel"><h2>Campaign</h2><p role="status">Loading post-compromise state…</p></section>

  const state = campaign.autopilot_state || {}
  const disabled = !!working || busy

  return <section className="panel campaign-panel">
    {actionError && <p className="inline-error" role="alert">{actionError}</p>}
    <div className="panel-title">
      <h2>Campaign</h2>
      <span className="muted">{campaign.footholds.length} foothold(s) · {campaign.loot.length} credential(s) · {campaign.hosts.length} host(s)</span>
    </div>

    <div className="campaign-blurb">
      <p>This is what the engagement has actually obtained. The kill chain drafts each next phase from this evidence only — a credential-validation step cannot exist without a recovered credential, and a lateral-movement step cannot exist without one that was proven to work.</p>
    </div>

    {!aggressive && <div className="notice" role="status">This target is not in aggressive lab mode, so the post-compromise kill chain is unavailable. Enable aggressive lab mode on the target (and have the letter authorize controlled exploitation) to unlock it.</div>}

    <section className="campaign-block">
      <div className="panel-title"><h3>Autopilot</h3>
        <span className="tag">{campaign.autopilot ? 'on' : 'off'}</span></div>
      <p className="muted">Semi-autonomous and opt-in. One iteration ingests the evidence from the steps you approved, drafts the next phase when the framework allows it, and records fresh proposals — it never approves or runs a command. Iteration {state.iterations || 0} of {campaign.autopilot_iteration_budget}.</p>
      {state.next_action && <p><b>Next human action:</b> {state.next_action}</p>}
      {state.stopped && <p className="muted"><b>Idle because:</b> {state.stopped}</p>}
      <div className="campaign-actions">
        <button disabled={disabled || !aggressive} onClick={() => setAutopilot(!campaign.autopilot)}>
          {working === 'autopilot' ? 'Saving…' : campaign.autopilot ? 'Turn autopilot off' : 'Turn autopilot on'}
        </button>
        <button className="secondary" disabled={disabled || !campaign.autopilot} onClick={runIteration}>
          {working === 'run' ? 'Running…' : 'Run one iteration'}
        </button>
      </div>
    </section>

    <section className="campaign-block">
      <h3>Footholds</h3>
      {campaign.footholds.length ? <div className="table-scroll" role="region" aria-label="Footholds table" tabIndex={0}><table className="campaign-table"><thead><tr><th>Host</th><th>Kind</th><th>Session</th><th>User</th><th>Privilege</th><th>State</th><th>Source</th></tr></thead>
        <tbody>{campaign.footholds.map(row => <tr key={row.id}>
          <td><code>{row.host}</code></td><td>{row.kind}</td><td>{row.remote_id || '—'}</td>
          <td>{row.username || '—'}</td><td>{row.privilege || '—'}</td>
          <td>{row.state}{row.pivot_ready ? ' · pivot' : ''}</td><td>{row.source_tool || '—'}</td>
        </tr>)}</tbody></table></div> : <div className="empty">No foothold has been opened yet.</div>}
    </section>

    <section className="campaign-block">
      <h3>Recovered credentials</h3>
      {campaign.loot.length ? <div className="table-scroll" role="region" aria-label="Recovered credentials table" tabIndex={0}><table className="campaign-table"><thead><tr><th>Host</th><th>Service</th><th>Username</th><th>Kind</th><th>Secret</th><th>Validated</th><th>Actions</th></tr></thead>
        <tbody>{campaign.loot.map(row => <tr key={row.id}>
          <td><code>{row.host || '—'}</code></td><td>{row.service || '—'}</td><td>{row.username || '—'}</td>
          <td>{row.secret_kind}</td>
          <td><code>{revealed[row.id] ?? row.secret_masked}</code></td>
          <td>{row.validated ? 'yes' : 'no'}</td>
          <td>{revealed[row.id]
            ? <button className="secondary compact" onClick={() => hide(row.id)}>Hide</button>
            : <button className="secondary compact" disabled={disabled || !row.has_secret} onClick={() => reveal(row)}>Reveal</button>}</td>
        </tr>)}</tbody></table></div> : <div className="empty">No credential has been recovered yet.</div>}
      <small className="muted">Secrets are encrypted at rest and masked in every list view. Revealing one is a separate, logged action.</small>
    </section>

    <section className="campaign-block">
      <h3>Discovered hosts</h3>
      {campaign.hosts.length ? <div className="table-scroll" role="region" aria-label="Discovered hosts table" tabIndex={0}><table className="campaign-table"><thead><tr><th>Address</th><th>Hostname</th><th>Role</th><th>State</th><th>Actions</th></tr></thead>
        <tbody>{campaign.hosts.map(row => <tr key={row.id}>
          <td><code>{row.address}</code></td><td>{row.hostname || '—'}</td><td>{row.role}</td><td>{row.state}</td>
          <td>{row.child_assessment_id
            ? <span className="tag good">child #{row.child_assessment_id}</span>
            : <button className="secondary compact" disabled={disabled || !aggressive} onClick={() => promote(row)}>Promote</button>}</td>
        </tr>)}</tbody></table></div> : <div className="empty">No host has been discovered yet.</div>}
      <small className="muted">Promoting a compromised host spawns a child assessment scoped to that host alone — strictly narrower than this one, so a pivot can never widen the engagement letter.</small>
    </section>
  </section>
}
