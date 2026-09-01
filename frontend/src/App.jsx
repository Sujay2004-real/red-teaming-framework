import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'
// Only used until /capabilities answers. The backend policy engine owns the
// real list, so a tool hardcoded here that policy rejects would just produce a
// step that fails at approval time.
const FALLBACK_CAPABILITIES = [{ id: 'tools', tools: ['nmap', 'traceroute', 'dig', 'nslookup', 'curl', 'whatweb', 'sslscan', 'nuclei'].map(name => ({ name })) }]
const emptyStep = tool => ({ tool: tool || 'nmap', command: '', reason: '', enabled: true })
// The backend falls back to a built-in plan for four different reasons; saying
// which one keeps a provider outage from looking like a successful AI plan.
const PLAN_SOURCE_NOTE = {
  'ai-filtered': 'Plan drafted by the configured AI provider and cleared by policy review.',
  'default-unconfigured': 'No AI provider is configured, so the built-in default plan was used. Add a base URL, model name, and API key to enable AI planning.',
  'default-provider-error': 'The AI provider could not be reached, so the built-in default plan was used.',
  'default-policy-rejected': 'Every AI-suggested command failed policy review, so the built-in default plan was used.',
  user: 'Using the plan you supplied.',
}
const detailText = detail => Array.isArray(detail) ? detail.map(item => item?.msg || JSON.stringify(item)).join('; ') : typeof detail === 'string' ? detail : ''
const samePlan = (a, b) => JSON.stringify(a || []) === JSON.stringify(b || [])
// The same formats and size cap the backend enforces on uploads, checked
// client-side so a wrong pick gets a readable message instead of silence or
// a raw 4xx from the server.
const ALLOWED_UPLOAD_SUFFIXES = ['.txt', '.md', '.pdf', '.docx']
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024
const fileSuffix = name => (name.match(/\.[^.]+$/) || [''])[0].toLowerCase()
// Request budgets. The backend caps a scanner run at 300 s and AI provider
// calls at 60 s, so the browser gives up only after the server itself
// certainly has, and `busy` can never wedge on a request that never answers.
const REQUEST_TIMEOUT_MS = 75_000
const EXECUTE_TIMEOUT_MS = 320_000
const HEALTH_POLL_MS = 10_000

// An objective drafted from the letter keeps the client's own framing: a
// baseline-restricted target says so plainly, a full assessment carries the
// letter's numbered objectives.
const suggestedObjective = (brief, target) => {
  const goals = (brief?.objectives || []).map(o => o.replace(/^[\d.]+\s*/, '')).join('; ')
  const baseline = (target.assessment_type || '').toLowerCase().includes('baseline')
  const headline = baseline
    ? `Baseline assessment of ${target.name}: ${target.assessment_type}`
    : `Assess ${target.name} per engagement ${brief?.engagement_ref || ''}`
  return (goals ? `${headline}. Objectives: ${goals}` : headline).slice(0, 1000)
}

function App() {
  const [targets, setTargets] = useState([]), [assessments, setAssessments] = useState([])
  const [selected, setSelected] = useState(null), [notice, setNotice] = useState(''), [busy, setBusy] = useState(false)
  // Server plan lives on `selected`; `draftPlan` holds unsaved edits so the
  // progress gauges below can never describe a plan the backend has not seen.
  const [draftPlan, setDraftPlan] = useState([])
  const [capabilities, setCapabilities] = useState(FALLBACK_CAPABILITIES)
  const [target, setTarget] = useState({ name: '', scope_domain_ip: '', authorized_scopes: '', criticality: 70 })
  const [assessment, setAssessment] = useState({ target_id: '', objective: '', requirements: '' })
  const [requirementFile, setRequirementFile] = useState(null)
  // The hidden file input behind the dropzone. The whole box is clickable,
  // so the picker is opened programmatically through this ref.
  const briefFileRef = useRef(null)
  // The parsed client engagement letter: what the agent was asked to do.
  const [brief, setBrief] = useState(null), [briefFilename, setBriefFilename] = useState(''), [briefText, setBriefText] = useState('')
  // Blank, not pre-filled: the operator chooses their own provider endpoint and
  // model. The input placeholders show the expected shape without submitting it.
  const [settings, setSettings] = useState({ gemini_api_key: '', api_base_url: '', model_name: '', proxy_url: '', proxy_username: '', proxy_password: '', gemini_configured: false, proxy_configured: false, provider_ready: false })
  const [loading, setLoading] = useState(true)
  // Which agent card is mid-flight right now; '' means the crew is idle. Bound
  // to real request lifecycles rather than a timer, so an agent only ever
  // "works" while an actual request is in flight.
  const [activeAgent, setActiveAgent] = useState('')
  // Human-sentence activity feed, newest first, capped so a long session
  // stays readable.
  const [feed, setFeed] = useState([])
  const pushFeed = (text, kind = 'info') => setFeed(entries => [{ text, kind, at: Date.now() }, ...entries].slice(0, 30))
  // Live backend reachability, polled independently of any button so dead
  // buttons always have a visible cause instead of a silent failure.
  const [backendUp, setBackendUp] = useState(true)
  const backendUpRef = useRef(true)
  // The step whose approval request is mid-flight, so its own button says
  // "Running…" during a long command instead of looking disabled for no reason.
  const [runningStep, setRunningStep] = useState(null)
  // Set when a popup blocker swallowed the report tab; a plain link needs no
  // user gesture, so the report stays one click away.
  const [reportUrl, setReportUrl] = useState('')

  const request = async (path, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) => {
    // FormData bodies set their own multipart boundary; a JSON header on top
    // would corrupt the upload.
    const headers = options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const res = await fetch(API + path, { headers, ...options, signal: controller.signal })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(detailText(data.detail) || `Request failed (${res.status})`)
      return data
    } catch (e) {
      // "TypeError: Failed to fetch" points at the code; the stopped
      // container is the actual cause. An abort is the timeout firing.
      if (e.name === 'AbortError') throw new Error(`The backend did not answer within ${Math.round(timeoutMs / 1000)} seconds — it may be overloaded or restarting.`)
      if (e instanceof TypeError) throw new Error(`Cannot reach the backend at ${API} — is the stack running?`)
      throw e
    } finally {
      clearTimeout(timer)
    }
  }
  const refresh = async () => {
    const [t, a, s, c] = await Promise.all([request('/targets/'), request('/assessments/'), request('/settings'), request('/capabilities').catch(() => null)])
    setTargets(t); setAssessments(a); setSettings(v => ({ ...v, ...s }))
    if (Array.isArray(c) && c.length) setCapabilities(c)
  }
  const openAssessment = async id => {
    try { const data = await request(`/assessments/${id}`); setSelected(data); setDraftPlan(data.plan || []) }
    catch (e) { setNotice(e.message) }
  }
  /* eslint-disable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */
  useEffect(() => { refresh().catch(e => setNotice(e.message)).finally(() => setLoading(false)) }, [])
  /* eslint-enable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */
  /* eslint-disable react-hooks/exhaustive-deps */
  // A dead backend turns every button into a silent no-op, so reachability is
  // polled on its own schedule and announced in a banner. Coming back online
  // triggers a refresh, because the UI's data is stale by the length of the
  // outage.
  useEffect(() => {
    const check = async () => {
      let up = false
      try {
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), 5000)
        try { up = (await fetch(API + '/health', { signal: controller.signal })).ok } finally { clearTimeout(timer) }
      } catch { up = false }
      if (up && !backendUpRef.current) refresh().catch(() => { })
      backendUpRef.current = up
      setBackendUp(up)
    }
    check()
    const interval = setInterval(check, HEALTH_POLL_MS)
    return () => clearInterval(interval)
  }, [])
  /* eslint-enable react-hooks/exhaustive-deps */
  // The agent argument lights the matching crew card for exactly as long as
  // the request is in flight; the finally clause guarantees it clears even on
  // failure, so no agent is ever left "working" after a crash.
  const run = async (agent, fn) => { setBusy(true); setNotice(''); setActiveAgent(agent || ''); try { await fn() } catch (e) { setNotice(e.message) } finally { setBusy(false); setActiveAgent('') } }
  const saveSettings = e => run('', async () => {
    e.preventDefault()
    // Compare against what was stored before this save. Testing the submitted
    // proxy_url alone announced "clearing the proxy URL also cleared its stored
    // credentials" to every operator who had never configured a proxy at all.
    const clearedProxy = settings.proxy_configured && !settings.proxy_url
    await request('/settings', { method: 'PUT', body: JSON.stringify({ gemini_api_key: settings.gemini_api_key || '', api_base_url: settings.api_base_url || '', model_name: settings.model_name || '', proxy_url: settings.proxy_url || '', proxy_username: settings.proxy_username || '', proxy_password: settings.proxy_password || '' }) }); setSettings(v => ({ ...v, gemini_api_key: '', proxy_password: '' })); await refresh(); setNotice(clearedProxy ? 'Settings saved. Clearing the proxy URL also cleared its stored credentials.' : 'Settings saved. Secrets are masked after storage.')
  })
  const addTarget = e => run('registrar', async () => { e.preventDefault(); await request('/targets/', { method: 'POST', body: JSON.stringify({ ...target, criticality: Math.min(100, Math.max(0, Number(target.criticality) || 0)), authorized_scopes: target.authorized_scopes.split(',').map(x => x.trim()).filter(Boolean) }) }); setTarget({ name: '', scope_domain_ip: '', authorized_scopes: '', criticality: 70 }); await refresh(); pushFeed(`Registered “${target.name}” as an authorized target.`) })
  const createAssessment = e => run('planner', async () => { e.preventDefault(); let requirements = assessment.requirements; if (requirementFile) { const form = new FormData(); form.append('file', requirementFile); const data = await request('/requirements/extract', { method: 'POST', body: form }); requirements = data.text } const selectedTarget = targets.find(t => t.id === Number(assessment.target_id)); const briefApplies = !!brief && !!selectedTarget && brief.targets.some(t => t.address === selectedTarget.scope_domain_ip); const a = await request('/assessments/', { method: 'POST', body: JSON.stringify({ ...assessment, target_id: Number(assessment.target_id), requirements, ...(briefApplies ? { engagement_brief: brief } : {}) }) }); setAssessment({ target_id: '', objective: '', requirements: '' }); setRequirementFile(null); await refresh(); await openAssessment(a.id); pushFeed(`Drafted a ${a.plan.length}-step plan for assessment #${a.id}. Nothing runs until you approve it.`, a.plan_source === 'ai-filtered' ? 'ok' : 'info'); const dropped = a.restricted_steps_dropped || 0; setNotice((PLAN_SOURCE_NOTE[a.plan_source] || '') + (dropped ? ` Removed ${dropped} step${dropped > 1 ? 's' : ''} using tools the client's letter restricts for this target.` : '')) })
  const savePlan = () => run('planner', async () => { const id = selected.id; await request(`/assessments/${id}/plan`, { method: 'PUT', body: JSON.stringify({ plan: draftPlan }) }); await openAssessment(id); await refresh(); pushFeed(`Saved the edited plan for assessment #${id}.`); setNotice('Command plan saved and ready for individual approval.') })
  // The assessment id is captured up front so switching assessments
  // mid-request cannot write one assessment's results into another, and the
  // timeout exceeds the executor's own 300 s cap so the server always decides
  // how a command ends. runningStep lights the exact button that is
  // mid-flight, so a long command reads as progress rather than a dead UI.
  const execute = index => { setRunningStep(index); run('executor', async () => { const id = selected.id; const d = await request(`/assessments/${id}/execute`, { method: 'POST', body: JSON.stringify({ step_index: index, approved: true }) }, EXECUTE_TIMEOUT_MS); const r = d.result || {}; pushFeed(r.return_code === 0 ? `Step ${index + 1} finished cleanly in ${r.duration_ms} ms.` : `Step ${index + 1} exited with code ${r.return_code} — you can re-approve it.`, r.return_code === 0 ? 'ok' : 'warn'); await openAssessment(id); await refresh() }).finally(() => setRunningStep(null)) }
  const analyze = () => run('analyst', async () => { const id = selected.id; const d = await request(`/assessments/${id}/analyze`, { method: 'POST' }); await openAssessment(id); await refresh(); pushFeed(`Correlated the outputs into ${d.findings_count || 0} finding${(d.findings_count || 0) !== 1 ? 's' : ''} (${d.analyzer} mode).`, 'ok'); const failed = d.failed_steps || []; setNotice(failed.length ? `Analysis complete, but ${failed.length > 1 ? 'steps' : 'step'} ${failed.map(i => i + 1).join(', ')} failed to run — findings may be incomplete.` : `Analysis complete (${d.analyzer}).`) })
  const report = () => run('reporter', async () => { const id = selected.id; const d = await request(`/assessments/${id}/report`, { method: 'POST' }); const url = API + d.download_url; const opened = window.open(url, '_blank', 'noopener'); // A window.open that follows an await has lost its user gesture, so popup
  // blockers swallow it silently; a plain link needs no gesture, so the
  // report stays one click away instead of looking like a dead button.
  setReportUrl(opened ? '' : url); await openAssessment(id); await refresh(); pushFeed(opened ? 'Report written and opened in a new tab — it cites the engagement brief and every command.' : 'Report written — your browser blocked the automatic tab; open it from the link below.', 'ok') })
  // Validation runs before any request so a bad pick — wrong type, too
  // large, or a dropped folder, which arrives as no file at all — gets a
  // plain sentence instead of silence or a raw 4xx from the server.
  const importBrief = file => {
    if (!file) { setNotice('No file was selected. Click anywhere in the box to browse, or drop the letter onto it.'); return }
    if (!ALLOWED_UPLOAD_SUFFIXES.includes(fileSuffix(file.name))) { setNotice(`“${file.name}” is not a supported format. Use PDF, Word, Markdown or text.`); return }
    if (file.size > MAX_UPLOAD_BYTES) { setNotice(`“${file.name}” is larger than 5 MB, the maximum the reader accepts.`); return }
    return run('reader', async () => {
      const form = new FormData(); form.append('file', file)
      const data = await request('/engagement/parse', { method: 'POST', body: form })
      setBrief(data.engagement); setBriefFilename(data.filename); setBriefText(data.text || '')
      const n = data.engagement.targets.length
      pushFeed(`Read “${data.filename}” — ${n} authorized target${n > 1 ? 's' : ''}, ${data.engagement.objectives?.length || 0} objectives, ${data.engagement.out_of_scope?.length || 0} out-of-scope item${(data.engagement.out_of_scope?.length || 0) !== 1 ? 's' : ''}.`, 'ok')
      setNotice(`I've read “${data.filename}” — ${n} authorized target${n > 1 ? 's' : ''} found. Review the brief and register each target below.`)
    })
  }
  const registerBriefTarget = t => run('registrar', async () => {
    const created = await request('/targets/', {
      method: 'POST', body: JSON.stringify({
        name: t.name || t.address,
        scope_domain_ip: t.address,
        authorized_scopes: (t.scopes && t.scopes.length) ? t.scopes : [t.address],
        criticality: Number.isFinite(t.criticality) ? t.criticality : 70,
        restricted_tools: t.restricted_tools || [],
      })
    })
    await refresh()
    setAssessment({ target_id: String(created.id), objective: suggestedObjective(brief, t), requirements: briefText })
    pushFeed(`Registered “${created.name}”${created.restricted_tools?.length ? ` (no ${created.restricted_tools.join(', ')} per the letter)` : ''}.`, 'ok')
    setNotice(`“${created.name}” is registered${created.restricted_tools?.length ? ` — ${created.restricted_tools.join(', ')} will be refused on this target per the client's letter` : ''}. Now generate its command plan.`)
  })
  // One click from letter to ready-to-approve plans: register every target in
  // the brief, then draft an assessment for each so the operator lands on a
  // plan they can review. The crew cards alternate registrar/planner as the
  // loop moves between the two kinds of work.
  const setupFromBrief = () => run('registrar', async () => {
    let firstId = null, registered = 0, drafted = 0
    for (const t of brief.targets) {
      const existing = targets.find(x => x.scope_domain_ip === t.address)
      const target = existing || await request('/targets/', {
        method: 'POST', body: JSON.stringify({
          name: t.name || t.address,
          scope_domain_ip: t.address,
          authorized_scopes: (t.scopes && t.scopes.length) ? t.scopes : [t.address],
          criticality: Number.isFinite(t.criticality) ? t.criticality : 70,
          restricted_tools: t.restricted_tools || [],
        })
      })
      if (!existing) registered++
      setActiveAgent('planner')
      const a = await request('/assessments/', { method: 'POST', body: JSON.stringify({ target_id: target.id, objective: suggestedObjective(brief, t), requirements: briefText, engagement_brief: brief }) })
      drafted++
      if (firstId === null) firstId = a.id
      setActiveAgent('registrar')
    }
    await refresh(); await openAssessment(firstId)
    pushFeed(`Set up the whole letter: ${registered} target${registered !== 1 ? 's' : ''} registered, ${drafted} plan${drafted !== 1 ? 's' : ''} drafted. Each waits for your approval.`, 'ok')
    setNotice(`All set — ${drafted} plan${drafted !== 1 ? 's' : ''} drafted from the letter. Review the commands, then approve each one when you're ready.`)
  })
  const patchStep = (i, key, value) => setDraftPlan(plan => plan.map((s, n) => n === i ? { ...s, [key]: value } : s))
  const toolNames = useMemo(() => new Set(capabilities.flatMap(group => (group.tools || []).map(tool => tool.name))), [capabilities])
  const executionByStep = useMemo(() => new Map((selected?.executions || []).map(execution => [execution.step_index, execution])), [selected])
  // Gauges and the Analyze gate read the *saved* plan. Reading the draft let a
  // local "enabled" toggle light up Analyze while the backend still expected
  // the step to run, and the request then failed with a 409.
  const enabledSteps = useMemo(() => (selected?.plan || []).map((step, index) => ({ step, index })).filter(({ step }) => step.enabled !== false), [selected])
  const completedSteps = useMemo(() => enabledSteps.filter(({ index }) => executionByStep.get(index)?.complete), [enabledSteps, executionByStep])
  const planLocked = (selected?.executions?.length || 0) > 0
  const planDirty = !!selected && !samePlan(draftPlan, selected.plan)
  const selectedTarget = useMemo(() => targets.find(t => t.id === selected?.target_id), [targets, selected])
  const canAnalyze = !!selected && !planDirty && enabledSteps.length > 0 && completedSteps.length === enabledSteps.length
  const canReport = selected?.status === 'analyzed' || selected?.status === 'reported'

  // The agent pipeline the stepper visualises. Each stage reads only saved
  // state, so the tracker never claims progress the backend has not made.
  const stages = useMemo(() => {
    const registered = targets.length > 0
    const hasBrief = !!brief
    const planned = !!selected && (selected.plan || []).length > 0
    const findings = selected?.findings?.length || 0
    return [
      { key: 'read', label: 'Read the engagement letter', caption: hasBrief ? `Parsed ${brief.targets.length} target${brief.targets.length > 1 ? 's' : ''} from “${briefFilename}”` : 'Import the client PDF to set scope and rules', done: hasBrief },
      { key: 'register', label: 'Register authorized targets', caption: registered ? `${targets.length} target${targets.length > 1 ? 's' : ''} with scopes and criticality` : 'Scopes and criticality feed every policy check and score', done: registered },
      { key: 'plan', label: 'Draft the command plan', caption: planned ? `${enabledSteps.length} command${enabledSteps.length !== 1 ? 's' : ''} awaiting your approval` : 'The agent proposes; nothing runs until you approve', done: planned },
      { key: 'run', label: 'Approve & execute', caption: selected ? `${completedSteps.length} of ${enabledSteps.length} approved commands complete` : 'Every command needs your explicit approval', done: !!selected && completedSteps.length === enabledSteps.length && enabledSteps.length > 0 },
      { key: 'analyze', label: 'Correlate findings', caption: findings ? `${findings} correlated finding${findings > 1 ? 's' : ''}` : 'Dedupe and score severity, risk and confidence', done: selected?.status === 'analyzed' || selected?.status === 'reported' },
      { key: 'report', label: 'Deliver the report', caption: selected?.status === 'reported' ? 'Ready to download' : 'Signed-off evidence for the client', done: selected?.status === 'reported' },
    ]
  }, [targets, brief, briefFilename, selected, enabledSteps, completedSteps])

  // The agent crew the cards animate. `working` comes from the live request
  // lifecycle (`activeAgent`); `done` reads saved state only, so a card never
  // claims an agent finished work the backend has not recorded.
  const crew = useMemo(() => {
    const findings = selected?.findings?.length || 0
    const planned = !!selected && (selected.plan || []).length > 0
    return [
      { key: 'reader', emoji: '📄', name: 'Brief reader', idle: 'Waiting for the client letter', working: 'Reading the letter…', done: !!brief, doneText: briefFilename ? `Read “${briefFilename}”` : '' },
      { key: 'registrar', emoji: '🗂️', name: 'Registrar', idle: 'Registers authorized targets', working: 'Registering targets…', done: targets.length > 0, doneText: targets.length ? `${targets.length} target${targets.length !== 1 ? 's' : ''} on file` : '' },
      { key: 'planner', emoji: '🧭', name: 'Planner', idle: 'Drafts commands for your approval', working: 'Drafting the command plan…', done: planned, doneText: planned ? `${(selected.plan || []).length} steps awaiting approval` : '' },
      { key: 'executor', emoji: '⚡', name: 'Executor', idle: 'Runs only what you approve', working: 'Running the approved command…', done: completedSteps.length > 0, doneText: completedSteps.length ? `${completedSteps.length}/${enabledSteps.length} commands complete` : '' },
      { key: 'analyst', emoji: '🔎', name: 'Analyst', idle: 'Correlates and scores findings', working: 'Correlating outputs…', done: selected?.status === 'analyzed' || selected?.status === 'reported', doneText: findings ? `${findings} finding${findings !== 1 ? 's' : ''} scored` : '' },
      { key: 'reporter', emoji: '📝', name: 'Reporter', idle: 'Writes the client report', working: 'Writing the report…', done: selected?.status === 'reported', doneText: selected?.status === 'reported' ? 'Report ready to download' : '' },
    ]
  }, [brief, briefFilename, targets, selected, completedSteps, enabledSteps])
  const workingAgent = crew.find(agent => agent.key === activeAgent)
  // Buttons explain themselves while their own agent works, so a minute-long
  // request reads as progress instead of a dead button.
  const agentBusy = agent => busy && activeAgent === agent

  if (loading) return <main className="loading-screen"><div className="loading-mark" /><p>Loading control center...</p></main>

  return <main>
    {busy && <div className="busy-bar" aria-hidden="true" />}
    {!backendUp && <div className="offline-banner">⚠ Cannot reach the backend at <code>{API}</code> — buttons will not respond until the stack is running again.</div>}
    <header><div><span className="eyebrow">AUTHORIZED SECURITY ORCHESTRATION</span><h1>Red Team Control Center</h1><p>Hand me the client's letter — I'll draft the plan, and every command waits for your approval.</p></div><div className="health"><i /> Lab environment</div></header>
    {notice && <div className="notice">{notice}<button onClick={() => setNotice('')}>×</button></div>}
    <section className="stats"><div><b>{targets.length}</b><span>Authorized targets</span></div><div><b>{assessments.length}</b><span>Assessments</span></div><div><b>{assessments.filter(a => a.status === 'reported').length}</b><span>Reports completed</span></div><div><b>{settings.provider_ready ? 'AI' : 'Local'}</b><span>Configured analyzer</span></div></section>

    <div className="workspace">
      <aside>
        <section className="panel"><div className="panel-title"><h2>Configuration</h2><span className={settings.provider_ready ? 'tag good' : 'tag'}>{settings.provider_ready ? 'AI provider ready' : 'Fallback mode'}</span></div><form onSubmit={saveSettings}>
          <div className="provider-fields"><label>Base URL<input type="url" placeholder="https://your-provider.example/v1" value={settings.api_base_url || ''} onChange={e => setSettings({ ...settings, api_base_url: e.target.value })} /><small>Your own OpenAI-compatible endpoint. No provider is assumed.</small></label><label>Model name<input placeholder="your-model-name" value={settings.model_name || ''} onChange={e => setSettings({ ...settings, model_name: e.target.value })} /></label><label>API key<input type="password" placeholder={settings.gemini_configured ? 'Configured ••••••••' : 'Enter your own API key'} value={settings.gemini_api_key} onChange={e => setSettings({ ...settings, gemini_api_key: e.target.value })} /><small>{settings.gemini_configured ? 'Leave blank to keep the stored key.' : 'Encrypted before storage and never returned by the API.'}</small></label></div>
          <small className="plan-note">All three are needed for AI planning and analysis. Leave them blank to run entirely on the local deterministic analyzer.</small>
          <label>HTTP/S proxy<input placeholder="http://proxy:8080" value={settings.proxy_url || ''} onChange={e => setSettings({ ...settings, proxy_url: e.target.value })} /><small>Clearing this also clears the credentials below.</small></label>
          <div className="split"><label>Username<input value={settings.proxy_username || ''} onChange={e => setSettings({ ...settings, proxy_username: e.target.value })} /></label><label>Password<input type="password" value={settings.proxy_password || ''} onChange={e => setSettings({ ...settings, proxy_password: e.target.value })} /></label></div>
          <button className="secondary" disabled={busy}>{busy ? 'Saving…' : 'Save configuration'}</button><small>Responses never return secret values.</small>
        </form></section>
        <section className="panel"><h2>Add authorized target</h2><form onSubmit={addTarget}><label>Display name<input required value={target.name} onChange={e => setTarget({ ...target, name: e.target.value })} placeholder="Juice Shop lab" /></label><label>Primary host<input required value={target.scope_domain_ip} onChange={e => setTarget({ ...target, scope_domain_ip: e.target.value })} placeholder="juice-shop:3000" /></label><label>Allowed domains / CIDRs<input value={target.authorized_scopes} onChange={e => setTarget({ ...target, authorized_scopes: e.target.value })} placeholder="juice-shop, 172.18.0.0/16" /></label><label>Asset criticality<input type="number" min="0" max="100" required value={target.criticality} onChange={e => setTarget({ ...target, criticality: e.target.value })} /><small>0-100. Feeds the priority score of every finding on this target.</small></label><button disabled={busy}>{agentBusy('registrar') ? 'Registering…' : 'Add target'}</button></form></section>
        {/* The requirements picker clears its value after reading the file,
            so choosing the same document again still fires onChange. */}
        <section className="panel"><h2>New assessment</h2><form onSubmit={createAssessment}><label>Target<select required value={assessment.target_id} onChange={e => setAssessment({ ...assessment, target_id: e.target.value })}><option value="">Select target</option>{targets.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label><label>Objective<textarea required value={assessment.objective} onChange={e => setAssessment({ ...assessment, objective: e.target.value })} placeholder="Identify high-risk web vulnerabilities before release" /></label><label>Client requirements<input type="file" accept=".txt,.md,.pdf,.docx" onChange={e => { const file = e.target.files?.[0] || null; e.target.value = ''; setRequirementFile(file) }} /><small>{assessment.requirements ? `Context from “${briefFilename}” is attached and will guide planning.` : 'Optional planning context; every command still needs HITL approval.'}</small></label><button disabled={busy}>{agentBusy('planner') ? 'Drafting the plan…' : brief ? 'Draft plan from the letter' : 'Generate command plan'}</button></form></section>
      </aside>

      <section className="main-column">
        <section className="panel brief-panel">
          <div className="panel-title"><div><span className="eyebrow">START HERE</span><h2>Read the client's letter</h2></div>{brief && <button className="secondary compact" onClick={() => { setBrief(null); setBriefFilename(''); setBriefText('') }} disabled={busy}>Clear</button>}</div>
          {/* The whole box is the picker: clicks and Enter/Space forward to
              the hidden input, which clears itself after every pick so
              re-choosing the same file still fires onChange. */}
          {!brief ? <div className="dropzone" role="button" tabIndex={0} aria-label="Import the client engagement letter"
            onClick={() => { if (!busy) briefFileRef.current?.click() }}
            onKeyDown={e => { if (!busy && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); briefFileRef.current?.click() } }}
            onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); if (!busy) importBrief(e.dataTransfer.files?.[0]) }}>
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v11m0 0 4-4m-4 4-4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" /></svg>
            <label className="drop-pick" htmlFor="brief-file" onClick={e => e.stopPropagation()}>{briefFilename || 'Drop the request letter here'}</label>
            <input id="brief-file" type="file" accept=".txt,.md,.pdf,.docx" hidden ref={briefFileRef}
              onChange={e => { const file = e.target.files?.[0] || null; e.target.value = ''; importBrief(file) }} />
            <small>PDF, Word or text. I'll read it and work out the scope, targets, criticality and rules of engagement — then wait for your approval on every command.</small>
          </div> : <>
            <p className="brief-meta"><b>{brief.client_name || 'Client'}</b>{brief.engagement_ref && <> · engagement <code>{brief.engagement_ref}</code></>}{brief.test_window && <> · test window {brief.test_window}</>}</p>
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
                  </div>
                  {registered
                    ? <span className="registered-note">Registered ✓</span>
                    : <button className="compact" onClick={() => registerBriefTarget(t)} disabled={busy}>{agentBusy('registrar') ? 'Registering…' : 'Register this target'}</button>}
                </div>
              })}
            </div>
            <div className="brief-actions">
              <button onClick={setupFromBrief} disabled={busy}>{agentBusy('registrar') || agentBusy('planner') ? 'Setting up…' : 'Set up everything from this letter'}</button>
              <small>Registers every target above and drafts a plan for each. Still your call on every command — nothing runs until you approve it.</small>
            </div>
            {!!brief.objectives?.length && <details className="brief-details" open><summary>What the client asked for ({brief.objectives.length})</summary><ol>{brief.objectives.map((o, i) => <li key={i}>{o}</li>)}</ol></details>}
            {(!!brief.out_of_scope?.length || !!brief.prohibited?.length) && <details className="brief-details"><summary>Out of scope ({brief.out_of_scope?.length || 0}) & prohibited techniques ({brief.prohibited?.length || 0})</summary>
              {!!brief.out_of_scope?.length && <><b>Never touch</b><ul>{brief.out_of_scope.map((o, i) => <li key={i}>{o}</li>)}</ul></>}
              {!!brief.prohibited?.length && <><b>Never do</b><ul>{brief.prohibited.map((p, i) => <li key={i}>{p}</li>)}</ul></>}
            </details>}
          </>}
        </section>

        <section className="panel crew-panel"><div className="panel-title"><div><span className="eyebrow">LIVE</span><h2>The agent crew</h2></div><span className={activeAgent ? 'tag good' : 'tag'}>{workingAgent ? `${workingAgent.name} is working…` : 'Standing by'}</span></div>
          <div className="crew">
            {crew.map(agent => <div className={`crew-card${activeAgent === agent.key ? ' working' : ''}${agent.done && activeAgent !== agent.key ? ' done' : ''}`} key={agent.key}>
              <span className="crew-avatar" aria-hidden="true">{agent.emoji}</span>
              <b>{agent.name}</b>
              <small>{activeAgent === agent.key ? agent.working : agent.done ? agent.doneText : agent.idle}</small>
            </div>)}
          </div>
          {!!feed.length && <div className="feed-wrap"><div className="panel-title"><h2>What just happened</h2><button className="secondary compact" onClick={() => setFeed([])} disabled={busy}>Clear</button></div>
            <ul className="feed">{feed.map((entry, i) => <li key={entry.at + '-' + i} className={entry.kind}><span className="feed-time">{new Date(entry.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>{entry.text}</li>)}</ul>
          </div>}
        </section>

        <section className="panel pipeline-panel"><div className="panel-title"><h2>Where the agent is</h2><span className="muted">{selected ? `Assessment #${selected.id} · ${targets.find(t => t.id === selected.target_id)?.name || ''}` : 'No assessment selected yet'}</span></div>
          <ol className="pipeline">
            {stages.map((stage, i) => {
              const active = !stage.done && stages.slice(0, i).every(s => s.done)
              return <li key={stage.key} className={`${stage.done ? 'done' : ''} ${active ? 'active' : ''}`}>
                <span className="stage-dot">{stage.done ? '✓' : i + 1}</span>
                <span className="stage-body"><b>{stage.label}</b><small>{stage.caption}</small></span>
              </li>
            })}
          </ol>
        </section>

        <section className="panel"><div className="panel-title"><h2>Assessments</h2><span className="muted">Select a run to inspect</span></div><div className="assessment-list">{assessments.length === 0 ? <div className="empty">Create your first authorized assessment.</div> : assessments.map(a => <button key={a.id} className={`assessment-row ${selected?.id === a.id ? 'active' : ''}`} onClick={() => { setReportUrl(''); openAssessment(a.id) }} disabled={busy}><span><b>#{a.id} · {targets.find(t => t.id === a.target_id)?.name || 'Target'}</b><small>{a.objective}</small></span><span className={`status ${a.status}`}>{a.status.replaceAll('_', ' ')}</span></button>)}</div></section>

        {selected && <>
          <section className="panel"><div className="panel-title"><div><span className="eyebrow">ASSESSMENT #{selected.id}</span><h2>Editable command plan</h2></div><button className="secondary compact" onClick={savePlan} disabled={busy || planLocked || !planDirty}>{agentBusy('planner') ? 'Saving…' : 'Save plan'}</button></div><p className="muted intro">Review every command before execution. Enabled steps require approval and pass policy checks.</p>
            {!!selectedTarget?.restricted_tools?.length && <small className="plan-note">Client's letter for this target: {selectedTarget.restricted_tools.join(', ')} {selectedTarget.restricted_tools.length > 1 ? 'are' : 'is'} restricted and will be refused at approval.</small>}
            <div className="plan">{draftPlan.map((step, i) => {
              const execution = executionByStep.get(i)
              const running = !!execution && !execution.complete
              const executed = !!execution && execution.complete
              const retryable = !!execution?.retryable
              const savedStep = selected.plan?.[i]
              const locked = planLocked || running
              const inFlight = runningStep === i
              const label = inFlight ? 'Running…' : running ? 'Running...' : retryable ? 'Re-approve & retry' : executed ? 'Executed' : 'Approve & execute'
              const state = inFlight || running ? 'Execution in progress'
                : executed && execution.return_code === 0 ? `Execution logged${execution.attempt > 1 ? ` (attempt ${execution.attempt})` : ''}`
                  : executed ? `Did not succeed (exit ${execution.return_code}) after ${execution.attempt} attempt${execution.attempt > 1 ? 's' : ''}`
                    : planDirty ? 'Save the plan before approving'
                      : 'Awaiting explicit approval'
              return <div className={`step ${step.enabled === false ? 'disabled-step' : ''}`} key={i}>
                <div className="step-head"><span className="step-number">{i + 1}</span>
                  <select value={step.tool} onChange={e => patchStep(i, 'tool', e.target.value)} disabled={locked}>
                    {!toolNames.has(step.tool) && <option value={step.tool}>{step.tool} (not permitted)</option>}
                    {capabilities.map(group => <optgroup key={group.id} label={String(group.id).replaceAll('_', ' ')}>{(group.tools || []).map(tool => <option key={tool.name} value={tool.name}>{tool.name}</option>)}</optgroup>)}
                  </select>
                  <label className="toggle"><input type="checkbox" checked={step.enabled !== false} onChange={e => patchStep(i, 'enabled', e.target.checked)} disabled={locked} /><span /> Enabled</label>
                  <button className="icon-btn" title="Remove step" aria-label="Remove step" onClick={() => setDraftPlan(plan => plan.filter((_, n) => n !== i))} disabled={locked}>×</button>
                </div>
                <input className="command" value={step.command} onChange={e => patchStep(i, 'command', e.target.value)} disabled={locked} />
                <input value={step.reason || ''} onChange={e => patchStep(i, 'reason', e.target.value)} placeholder="Why this command is needed" disabled={locked} />
                <div className="step-actions"><span className={executed && execution.return_code === 0 ? 'step-complete' : retryable ? 'step-failed' : ''}>{state}</span>
                  <button disabled={busy || step.enabled === false || running || (executed && !retryable) || planDirty || !savedStep} onClick={() => execute(i)}>{label}</button>
                </div>
              </div>
            })}</div>
            <button className="secondary" onClick={() => setDraftPlan(plan => [...plan, emptyStep(capabilities[0]?.tools?.[0]?.name)])} disabled={planLocked}>Add command</button>
            {draftPlan.length === 0 && <div className="empty">Add at least one command to continue.</div>}
            {planLocked && <small className="plan-note">Execution has started, so this plan is locked. Failed or abandoned steps can still be re-approved individually.</small>}
            {!planLocked && planDirty && <small className="plan-note">Unsaved plan edits. Save the plan so approvals run the commands shown here.</small>}
          </section>

          <section className="panel action-panel"><div><h2>Analysis & report</h2><p>Correlates outputs, removes duplicate findings, and calculates transparent risk and priority scores.</p><span className="action-status">{canAnalyze ? 'All enabled steps complete' : `${completedSteps.length}/${enabledSteps.length || 0} enabled steps complete${planDirty ? ' · unsaved plan edits' : ''}`}</span></div><div><button className="secondary" onClick={analyze} disabled={busy || !canAnalyze}>{agentBusy('analyst') ? 'Analyzing…' : 'Analyze results'}</button><button onClick={report} disabled={busy || !canReport}>{agentBusy('reporter') ? 'Writing the report…' : 'Generate report'}</button>{reportUrl && <a className="download-link report-fallback" href={reportUrl} target="_blank" rel="noreferrer">Your browser blocked the report tab — open it here</a>}{selected.status === 'reported' && <a className="download-link" href={`${API}/reports/${selected.id}`} target="_blank" rel="noreferrer">Download last report</a>}</div></section>

          {!!selected.findings?.length && <section className="panel"><div className="panel-title"><h2>Prioritized findings</h2><span className="tag good">{selected.findings.length} correlated</span></div><div className="findings">{selected.findings.map(f => <article key={f.id}><div><span className={`severity ${f.severity}`}>{f.severity}</span><h3>{f.title}</h3><p>{f.description}</p>{!!f.source_tools?.length && <small>Reported by {f.source_tools.join(', ')}</small>}</div><div className="scores"><span><b>{f.priority_score}</b>Priority</span><span><b>{f.risk_score}</b>Risk / 125</span><span><b>{f.confidence_score}%</b>Confidence</span></div><details><summary>Evidence and remediation</summary><pre>{f.evidence}</pre><p><b>Fix:</b> {f.remediation}</p></details></article>)}</div></section>}

          {!!selected.executions?.length && <section className="panel"><h2>Execution audit trail</h2><div className="audit">{selected.executions.map(e => <details key={e.id}><summary><b>{e.tool_name}</b><code>{e.command}</code><span className={!e.complete ? 'muted' : e.return_code === 0 ? 'ok' : 'fail'}>{e.complete ? `exit ${e.return_code} · ${e.duration_ms} ms` : 'still running'}{e.attempt > 1 ? ` · attempt ${e.attempt}` : ''}</span></summary><pre>{e.stdout || 'No standard output returned.'}</pre>{!!e.stderr && <pre className="stderr">{e.stderr}</pre>}</details>)}</div></section>}
        </>}
      </section>
    </div>
    <footer>For authorized laboratory environments only · Human approval required before every command</footer>
  </main>
}
export default App