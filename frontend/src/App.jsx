import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import { useAssessment } from './lib/useAssessment'
import { useExecution } from './lib/useExecution'
import { useRecommendations } from './lib/useRecommendations'
import ReportVersions from './components/ReportVersions'
import ScopePolicy from './components/ScopePolicy'
import {
  API, HEALTH_POLL_MS,
  createRequest, fetchProtectedObjectUrl, getOperatorKey, loadStoredKey, setOperatorKey,
} from './lib/api'
import {
  FALLBACK_CAPABILITIES, PHASES, PHASE_LABEL, PLAN_SOURCE_NOTE, samePlan, suggestedObjective,
} from './lib/constants'
import { AppContext } from './lib/AppContext'
import ApiKeyGate from './components/ApiKeyGate'
import ConfigurationPanel from './components/ConfigurationPanel'
import TargetPanel from './components/TargetPanel'
import NewAssessmentPanel from './components/NewAssessmentPanel'
import LetterPanel from './components/LetterPanel'
import CrewPanel from './components/CrewPanel'
import PhasePipeline from './components/PhasePipeline'
import AssessmentsPanel from './components/AssessmentsPanel'
import PlanEditor from './components/PlanEditor'
import AnalysisPanel from './components/AnalysisPanel'
import FindingsPanel from './components/FindingsPanel'
import AuditTrailPanel from './components/AuditTrailPanel'

// The single-page control center. App owns the shared state and the request
// lifecycle; each panel in components/ renders one slice of it and receives
// exactly the data it needs. The panels never hold secrets and read only
// server-confirmed state.
function App() {
  const [targets, setTargets] = useState([]), [assessments, setAssessments] = useState([])
  const [notice, setNotice] = useState(''), [busy, setBusy] = useState(false)
  const [page, setPage] = useState('Assessments'), [tab, setTab] = useState('Overview')
  const [rememberKey, setRememberKey] = useState(false)
  const [catalogPage, setCatalogPage] = useState(0), [catalogTotal, setCatalogTotal] = useState(0)
  const [reviewedPolicy, setReviewedPolicy] = useState({ max_executions: 100, max_rate: 30 })
  // Server plan lives on `selected`; `draftPlan` holds unsaved edits so the
  // progress gauges below can never describe a plan the backend has not seen.

  // The adaptive next-step proposals for the assessment in view: the last
  // /next-steps response (manual or automatic), and which of its candidates
  // the operator has ticked. Proposals are never a plan on their own — they
  // only become one when the operator adds them to the draft and saves,
  // exactly like a hand-typed step.
  const [nextProposals, setNextProposals] = useState(null)
  const [pickedCandidates, setPickedCandidates] = useState(new Set())
  const [capabilities, setCapabilities] = useState(FALLBACK_CAPABILITIES)
  const [target, setTarget] = useState({ name: '', scope_domain_ip: '', authorized_scopes: '', criticality: 70 })
  const [assessment, setAssessment] = useState({ target_id: '', objective: '', requirements: '' })
  const [requirementFile, setRequirementFile] = useState(null)
  // Two ways into an assessment: mode 'letter' drives one registered target
  // (the PDF import path), mode 'prompt' lets the operator pick several
  // targets and describe the engagement in their own words.
  const [assessmentMode, setAssessmentMode] = useState('letter')
  // Mode 'prompt' state: which registered targets the operator picked, and
  // the free-text engagement prompt the framework plans from.
  const [promptTargetIds, setPromptTargetIds] = useState([])
  const [promptText, setPromptText] = useState('')
  // The parsed client engagement letter: what the agent was asked to do.
  const [brief, setBrief] = useState(null), [briefFilename, setBriefFilename] = useState(''), [briefText, setBriefText] = useState('')
  // Blank, not pre-filled: the operator chooses their own provider endpoint and
  // model. The input placeholders show the expected shape without submitting it.
  const [settings, setSettings] = useState({ gemini_api_key: '', api_base_url: '', model_name: '', proxy_url: '', proxy_username: '', proxy_password: '', gemini_configured: false, proxy_configured: false, proxy_password_configured: false, provider_ready: false, execution_mode: 'local', ssh_host: '', ssh_port: 22, ssh_username: '', ssh_password: '', ssh_password_configured: false })
  // The last "Test connection" result against the Kali attacker VM: the
  // machine's real identity (OS, kernel, SSH host key) and tool inventory,
  // shown so the operator — and an audience — can see which box will run
  // the approved commands.
  const [sshTest, setSshTest] = useState(null)
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

  // Set when a popup blocker swallowed the report tab; a plain link needs no
  // user gesture, so the report stays one click away.
  const [reportUrl, setReportUrl] = useState('')
  // Live terminal: which execution is being streamed, and the output fetched
  // so far. The command's real output scrolls in as the scanner produces it.

  // Elapsed seconds for the running command's status line, ticking locally
  // between polls so the terminal never looks frozen.


  // The operator API key, entered once and remembered per browser. A 401 from
  // the backend raises the key prompt; until a valid key is saved, protected
  // endpoints are unreachable by design. The live value lives in api.js (the
  // request wrapper reads it at call time); this state only drives re-render.
  const [apiKey, setApiKey] = useState(loadStoredKey)
  const [keyInput, setKeyInput] = useState('')
  const [keyPrompt, setKeyPrompt] = useState(false)

  const request = useMemo(
    () => createRequest(getOperatorKey, () => setKeyPrompt(true)),
    [])

  const refresh = async () => {
    const [t, a, s, c] = await Promise.all([request('/targets/'), request(`/catalog/assessments?offset=${catalogPage * 30}&limit=30`), request('/settings'), request('/capabilities').catch(() => null)])
    setTargets(t); setAssessments(a.items); setCatalogTotal(a.total); setSettings(v => ({ ...v, ...s }))
    if (Array.isArray(c) && c.length) setCapabilities(c)
  }
  const { selected, draftPlan, setDraftPlan, openAssessment, reloadAssessment, clearAssessment } = useAssessment(request, setNotice)
  const { runningStep, liveExec, liveElapsed } = useExecution(selected, request,
    async id => { await reloadAssessment(id); await refresh(); pushFeed('Execution finished; evidence and attempt history are available in Activity.') }, setNotice)
  useRecommendations(selected?.id, request, batch => { setNextProposals(batch); setPickedCandidates(new Set()) })
  /* eslint-disable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */
  useEffect(() => { refresh().catch(e => setNotice(e.message)).finally(() => setLoading(false)) }, [apiKey, catalogPage])
  /* eslint-enable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */

  // Saving the key retries the whole refresh immediately, so the operator
  // sees the workspace the moment the key is right instead of reloading.
  const saveApiKey = e => {
    e.preventDefault()
    const value = keyInput.trim()
    if (!value) return
    setOperatorKey(value, rememberKey)
    setApiKey(value)
    setKeyInput('')
    setKeyPrompt(false)
  }
  /* eslint-disable react-hooks/exhaustive-deps */
  // A dead backend turns every button into a silent no-op, so reachability is
  // polled on its own schedule and announced in a banner. Coming back online
  // triggers a refresh, because the UI's data is stale by the length of the
  // outage. /health needs no operator key, so the poll works pre-unlock.
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
  // Buttons explain themselves while their own agent works, so a minute-long
  // request reads as progress instead of a dead UI.
  const agentBusy = agent => busy && activeAgent === agent

  // The single payload both "Save configuration" and "Test connection" send,
  // so the connection test always probes exactly what is on screen.
  const settingsPayload = () => JSON.stringify({
    gemini_api_key: settings.gemini_api_key || '', api_base_url: settings.api_base_url || '',
    model_name: settings.model_name || '', proxy_url: settings.proxy_url || '',
    proxy_username: settings.proxy_username || '', proxy_password: settings.proxy_password || '',
    execution_mode: settings.execution_mode || 'local', ssh_host: settings.ssh_host || '',
    ssh_port: Math.min(65535, Math.max(1, Number(settings.ssh_port) || 22)),
    ssh_fingerprint: settings.ssh_fingerprint || '', ssh_private_key: settings.ssh_private_key || '', ssh_key_passphrase: settings.ssh_key_passphrase || '',
    ssh_username: settings.ssh_username || '', ssh_password: settings.ssh_password || '',
  })
  const saveSettings = e => run('', async () => {
    e.preventDefault()
    // Compare against what was stored before this save. Testing the submitted
    // proxy_url alone announced "clearing the proxy URL also cleared its stored
    // credentials" to every operator who had never configured a proxy at all.
    const clearedProxy = settings.proxy_configured && !settings.proxy_url
    const clearedVm = settings.ssh_password_configured && !settings.ssh_host
    await request('/settings', { method: 'PUT', body: settingsPayload() })
    setSettings(v => ({ ...v, gemini_api_key: '', proxy_password: '', ssh_password: '', ssh_private_key: '', ssh_key_passphrase: '' }))
    await refresh()
    setNotice(clearedProxy ? 'Settings saved. Clearing the proxy URL also cleared its stored credentials.' : clearedVm ? 'Settings saved. Clearing the VM host also cleared its stored password.' : 'Settings saved. Secrets are masked after storage.')
  })
  // Saves the form first, then connects: the endpoint tests the stored
  // configuration, so what gets verified is what executions will use.
  const testSshConnection = () => run('', async () => {
    await request('/settings', { method: 'PUT', body: settingsPayload() })
    setSettings(v => ({ ...v, ssh_password: '' }))
    try {
      const result = await request('/settings/ssh-test', { method: 'POST' })
      setSshTest(result)
      pushFeed(`Reached the attacker VM ${result.user}@${result.host} — ${result.os}.`, 'ok')
      const problems = [...(result.tmux_ok ? [] : ['tmux']), ...(result.missing || [])]
      setNotice(problems.length
        ? `Connected to ${result.host}, but the VM is missing: ${problems.join(', ')}. Run “${result.install_hint}” inside the VM.`
        : `Kali VM verified: ${result.user}@${result.host} — ${result.os}, kernel ${result.kernel}. Approved commands will run in its tmux session.`)
    } catch (e) {
      setSshTest(null)
      throw e
    }
  })
  const addTarget = e => run('registrar', async () => { e.preventDefault(); await request('/targets/', { method: 'POST', body: JSON.stringify({ ...target, criticality: Math.min(100, Math.max(0, Number(target.criticality) || 0)), authorized_scopes: target.authorized_scopes.split(',').map(x => x.trim()).filter(Boolean), exploitation_authorized: !!target.exploitation_authorized, aggressive_lab: !!(target.exploitation_authorized && target.aggressive_lab) }) }); setTarget({ name: '', scope_domain_ip: '', authorized_scopes: '', criticality: 70, exploitation_authorized: false, aggressive_lab: false }); await refresh(); pushFeed(`Registered “${target.name}” as an authorized target.`) })
  const createAssessment = e => run('planner', async () => { e.preventDefault(); let requirements = assessment.requirements; if (requirementFile) { const form = new FormData(); form.append('file', requirementFile); const data = await request('/requirements/extract', { method: 'POST', body: form }); requirements = data.text } const selectedTarget = targets.find(t => t.id === Number(assessment.target_id)); const briefApplies = !!brief && !!selectedTarget && brief.targets.some(t => t.address === selectedTarget.scope_domain_ip); const a = await request('/assessments/', { method: 'POST', body: JSON.stringify({ ...assessment, target_id: Number(assessment.target_id), requirements, ...(briefApplies ? { engagement_brief: brief } : {}) }) }); setAssessment({ target_id: '', objective: '', requirements: '' }); setRequirementFile(null); await refresh(); await openAssessment(a.id); pushFeed(`Drafted a ${a.plan.length}-step plan for assessment #${a.id}. Nothing runs until you approve it.`, a.plan_source === 'ai-filtered' ? 'ok' : 'info'); const dropped = a.restricted_steps_dropped || 0; setNotice((PLAN_SOURCE_NOTE[a.plan_source] || '') + (dropped ? ` Removed ${dropped} step${dropped > 1 ? 's' : ''} using tools the client's letter restricts for this target.` : '')) })
  // The second way in: the operator picks one or more registered targets
  // and writes the engagement as their own prompt. The prompt becomes the
  // objective the planner plans from — with an AI provider configured it
  // steers the drafted commands, without one the policy-checked default
  // plan for each target is used. One assessment is drafted per target so
  // per-target scopes, criticality and letter restrictions still apply.
  const createFromPrompt = e => run('planner', async () => {
    e.preventDefault()
    const text = promptText.trim()
    if (!text) throw new Error('Write your prompt first — describe what this assessment should look for.')
    if (!promptTargetIds.length) throw new Error('Pick at least one registered target for this prompt.')
    const picked = promptTargetIds.map(id => targets.find(t => t.id === id)).filter(Boolean)
    if (!picked.length) throw new Error('The selected targets are no longer registered; pick again.')
    let firstId = null, totalDropped = 0
    for (const t of picked) {
      const a = await request('/assessments/', { method: 'POST', body: JSON.stringify({ target_id: t.id, objective: text }) })
      totalDropped += a.restricted_steps_dropped || 0
      if (firstId === null) firstId = a.id
    }
    await refresh(); await openAssessment(firstId)
    setPromptTargetIds([])
    pushFeed(`Drafted ${picked.length} plan${picked.length !== 1 ? 's' : ''} from your prompt for ${picked.map(t => t.name).join(', ')}. Nothing runs until you approve it.`, 'ok')
    setNotice(`Drafted ${picked.length} plan${picked.length !== 1 ? 's' : ''} from your prompt${totalDropped ? ` — ${totalDropped} step${totalDropped > 1 ? 's' : ''} using tools the client's letter restricts were removed` : ''}. Review the commands, then approve each one when you're ready.`)
  })
  const togglePromptTarget = id => setPromptTargetIds(ids => ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id])
  const savePlan = () => run('planner', async () => { const id = selected.id; await request(`/assessments/${id}/plan`, { method: 'PUT', body: JSON.stringify({ plan: draftPlan, plan_version: selected.plan_version }) }); await reloadAssessment(id); await refresh(); pushFeed(`Saved the edited plan for assessment #${id}.`); setNotice('Command plan saved and ready for individual approval.') })
  // The assessment id is captured up front so switching assessments
  // mid-request cannot write one assessment's results into another. The command
  // is queued in the background (the request returns as soon as the job is
  // accepted), and the live terminal reconnects to its output after the reload.
  // runningStep lights the exact button that is mid-flight, so a long command
  // reads as progress rather than a dead UI.
  const execute = index => run('executor', async () => {
    const id = selected.id
    await request(`/assessments/${id}/execute`, { method: 'POST', body: JSON.stringify({ step_index: index, approved: true, background: true, plan_version: selected.plan_version }) })
    await reloadAssessment(id)
    pushFeed(`Step ${index + 1} queued. You can reconnect to its output after a reload.`)
  })
  const cancelExecution = () => run('executor', async () => {
    const active = selected.executions.find(e => !e.complete)
    if (!active) return
    await request(`/assessments/${selected.id}/executions/${active.id}/cancel`, { method: 'POST' })
    setNotice('Cancellation requested. Waiting for the worker to stop the command.')
  })
  const analyze = () => run('analyst', async () => { const id = selected.id; const d = await request(`/assessments/${id}/analyze`, { method: 'POST' }); await reloadAssessment(id); await refresh(); pushFeed(`Correlated the outputs into ${d.findings_count || 0} finding${(d.findings_count || 0) !== 1 ? 's' : ''} (${d.analyzer} mode).`, 'ok'); const failed = d.failed_steps || []; const auto = d.auto_drafted; if (auto && auto.steps > 0) pushFeed(`Auto-drafted ${auto.steps} ${PHASE_LABEL(auto.phase).toLowerCase()} step${auto.steps !== 1 ? 's' : ''} from the findings — review and approve each one.`, 'ok'); if (auto && auto.note) pushFeed(`Next phase not drafted: ${auto.note}`, 'warn'); setNotice(failed.length ? `Analysis complete, but ${failed.length > 1 ? 'steps' : 'step'} ${failed.map(i => i + 1).join(', ')} failed to run — findings may be incomplete.` : (auto && auto.steps > 0 ? `Analysis complete (${d.analyzer}). ${auto.steps} ${PHASE_LABEL(auto.phase).toLowerCase()} step${auto.steps !== 1 ? 's' : ''} drafted from the findings — review them below.` : `Analysis complete (${d.analyzer}).`)) })
  // The report is downloaded through a key-authenticated blob fetch: the
  // plain /reports/{id} URL now requires the X-API-Key header, which a
  // browser tab link cannot send.
  const report = () => run('reporter', async () => {
    const id = selected.id
    const d = await request(`/assessments/${id}/report`, { method: 'POST' })
    const url = await fetchProtectedObjectUrl(d.download_url, getOperatorKey)
    const opened = window.open(url, '_blank', 'noopener')
    // A window.open that follows an await has lost its user gesture, so popup
    // blockers swallow it silently; a plain link needs no gesture, so the
    // report stays one click away instead of looking like a dead button.
    setReportUrl(opened ? '' : url)
    await reloadAssessment(id); await refresh()
    pushFeed(opened ? 'Report written and opened in a new tab — it cites the engagement brief and every command.' : 'Report written — your browser blocked the automatic tab; open it from the link below.', 'ok')
  })
  const downloadReport = () => run('reporter', async () => {
    const url = await fetchProtectedObjectUrl(`/reports/${selected.id}`, getOperatorKey)
    const opened = window.open(url, '_blank', 'noopener')
    if (!opened) setReportUrl(url)
  })
  const importBrief = file => {
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
        exploitation_authorized: !!t.exploitation_authorized,
        engagement_policy: reviewedPolicy,
      })
    })
    await refresh()
    setAssessment({ target_id: String(created.id), objective: suggestedObjective(brief, t), requirements: briefText })
    // The backend refuses to fork a second target for an address already on
    // file, so a stale register click says "already registered" instead of
    // silently creating the duplicate the letter never asked for.
    if (created.already_registered) {
      pushFeed(`“${created.name}” was already on file — reusing the registered target.`)
      setNotice(`“${created.name}” was already registered; the existing target is selected. Generate its command plan below.`)
      return
    }
    pushFeed(`Registered “${created.name}”${created.restricted_tools?.length ? ` (no ${created.restricted_tools.join(', ')})` : ''}${created.exploitation_authorized ? ' — the letter authorizes controlled verification' : ''}.`, 'ok')
    setNotice(`“${created.name}” is registered${created.restricted_tools?.length ? ` — ${created.restricted_tools.join(', ')} will be refused on this target per the client's letter` : ''}${created.exploitation_authorized ? ' and the letter authorizes controlled exploitation for it' : ''}. Now generate its command plan.`)
  })
  // One click from letter to ready-to-approve plans: register every target in
  // the brief, then draft an assessment for each so the operator lands on a
  // plan they can review. The crew cards alternate registrar/planner as the
  // loop moves between the two kinds of work. A target this same letter
  // already has an assessment for is skipped — re-running setup used to stack
  // a duplicate of every plan on top of the first run's (the "3 assessments
  // show as 6" bug). Clear the workspace first for a genuinely fresh run.
  const setupFromBrief = () => run('registrar', async () => {
    let firstId = null, registered = 0, drafted = 0, skipped = 0
    const letterRef = brief.engagement_ref
    const existingPlanFor = targetId => letterRef
      ? assessments.find(a => a.target_id === targetId && a.engagement_brief?.engagement_ref === letterRef)
      : null
    for (const t of brief.targets) {
      const existing = targets.find(x => x.scope_domain_ip === t.address)
      const created = existing || await request('/targets/', {
        method: 'POST', body: JSON.stringify({
          name: t.name || t.address,
          scope_domain_ip: t.address,
          authorized_scopes: (t.scopes && t.scopes.length) ? t.scopes : [t.address],
          criticality: Number.isFinite(t.criticality) ? t.criticality : 70,
          restricted_tools: t.restricted_tools || [],
          exploitation_authorized: !!t.exploitation_authorized,
        engagement_policy: reviewedPolicy,
        })
      })
      if (!existing) registered++
      const prior = existingPlanFor(created.id)
      if (prior) {
        skipped++
        if (firstId === null) firstId = prior.id
        continue
      }
      setActiveAgent('planner')
      const a = await request('/assessments/', { method: 'POST', body: JSON.stringify({ target_id: created.id, objective: suggestedObjective(brief, t), requirements: briefText, engagement_brief: brief }) })
      drafted++
      if (firstId === null) firstId = a.id
      setActiveAgent('registrar')
    }
    await refresh(); if (firstId !== null) await openAssessment(firstId)
    pushFeed(`Set up the whole letter: ${registered} target${registered !== 1 ? 's' : ''} registered, ${drafted} plan${drafted !== 1 ? 's' : ''} drafted${skipped ? `, ${skipped} already set up earlier` : ''}. Each waits for your approval.`, 'ok')
    setNotice(skipped
      ? `This letter was already set up: ${drafted} new plan${drafted !== 1 ? 's' : ''} drafted, ${skipped} target${skipped !== 1 ? 's' : ''} kept their existing assessment${skipped !== 1 ? 's' : ''}. Use “Clear workspace” first if you want a completely fresh run.`
      : `All set — ${drafted} plan${drafted !== 1 ? 's' : ''} drafted from the letter. Review the commands, then approve each one when you're ready.`)
  })
  const toolNames = useMemo(() => new Set(capabilities.flatMap(group => (group.tools || []).map(tool => tool.name))), [capabilities])
  const executionByStep = useMemo(() => new Map((selected?.executions || []).map(execution => [execution.step_index, execution])), [selected])
  // Gauges and the Analyze gate read the *saved* plan. Reading the draft let a
  // local "enabled" toggle light up Analyze while the backend still expected
  // the step to run, and the request then failed with a 409.
  const enabledSteps = useMemo(() => (selected?.plan || []).map((step, index) => ({ step, index })).filter(({ step }) => step.enabled !== false), [selected])
  const completedSteps = useMemo(() => enabledSteps.filter(({ index }) => executionByStep.get(index)?.complete), [enabledSteps, executionByStep])
  // Analysis is gated on the CURRENT phase's steps only: earlier phases were
  // already analyzed, and later phases have not been drafted yet.
  const currentPhase = selected?.current_phase || 'recon'
  const phaseSteps = useMemo(() => enabledSteps.filter(({ step }) => (step.phase || 'recon') === currentPhase), [enabledSteps, currentPhase])
  const phaseCompleted = useMemo(() => phaseSteps.filter(({ index }) => executionByStep.get(index)?.complete), [phaseSteps, executionByStep])
  const planLocked = (selected?.executions?.length || 0) > 0
  // What is actually frozen is the executed prefix, not the plan: an executed
  // step is an audit fact and keeps its tool, command and position, while an
  // unexecuted step — including one just proposed mid-engagement, or a whole
  // phase not yet run — stays editable. This is the same per-step rule the
  // plan-update endpoint enforces, and the reason a proposal can be accepted
  // in a phase that is already under way. Any change to the frozen prefix is
  // refused here and refused again by the backend.
  const planEditable = !selected?.executions?.some(e => { const old = selected.plan?.[e.step_index], next = draftPlan[e.step_index]; return !next || ['tool', 'command', 'phase', 'enabled'].some(k => old?.[k] !== next?.[k]) })
  const planDirty = !!selected && !samePlan(draftPlan, selected.plan)
  const selectedTarget = useMemo(() => targets.find(t => t.id === selected?.target_id), [targets, selected])
  const canAnalyze = !!selected && !planDirty && phaseSteps.length > 0 && phaseCompleted.length === phaseSteps.length
  const canReport = selected?.status === 'analyzed' || selected?.status === 'reported'

  // The engagement phases the stepper visualises. Each phase reads only
  // saved state (registered targets, parsed brief, current phase, analysis
  // records, report status), so the tracker never claims progress the
  // backend has not made.
  const phases = useMemo(() => {
    const registered = targets.length > 0
    const hasBrief = !!brief
    const current = selected?.current_phase || 'recon'
    const analyzed = new Set(selected?.analyzed_phases || [])
    const reported = selected?.status === 'reported'
    const plan = selected?.plan || []
    const phaseCount = p => plan.filter(step => (step.phase || 'recon') === p).length
    const phaseDone = p => phaseCount(p) > 0 && plan.filter(step => (step.phase || 'recon') === p && step.enabled !== false).every(step => executionByStep.get(plan.indexOf(step))?.complete)
    return PHASES.map(phase => {
      const { key, label, caption } = phase
      let done = false, captionText = caption
      if (key === 'scoping') {
        done = hasBrief && registered
        captionText = hasBrief && registered ? 'Letter read; targets registered' : caption
      } else if (key === 'recon') {
        done = analyzed.has('recon')
        captionText = selected ? (analyzed.has('recon') ? 'Recon executed and analyzed' : `${phaseDone('recon') ? 'All' : 'Some'} recon steps executed${analyzed.has('recon') ? '' : ' — analysis pending'}`) : caption
      } else if (key === 'vuln_analysis') {
        done = analyzed.has('recon') && (current !== 'vuln_analysis' || !!selected)
        captionText = analyzed.has('recon') ? `${selected?.finding_count || 0} correlated findings` : 'Analyze the recon output to complete this phase'
      } else if (key === 'exploitation') {
        done = analyzed.has('exploitation')
        captionText = done ? 'Findings verified with controlled exploits' : phaseCount('exploitation') ? `${phaseCount('exploitation')} verification steps planned` : selectedTarget?.exploitation_authorized ? 'Ready to draft verification steps from the findings' : 'Letter does not authorize exploitation for this target'
      } else if (key === 'post_exploitation') {
        done = analyzed.has('post_exploitation')
        captionText = done ? 'Bounded impact evidence collected' : phaseCount('post_exploitation') ? `${phaseCount('post_exploitation')} bounded steps planned` : 'Drafted after exploitation findings are analyzed'
      } else if (key === 'reporting') {
        done = reported
        captionText = reported ? 'Report ready to download' : 'Generated after the engagement evidence is complete'
      }
      return { key, label, caption: captionText, done }
    })
  }, [targets, brief, selected, selectedTarget, executionByStep])

  // Can the next phase's plan be drafted right now? Requires the previous
  // phase analyzed, and the letter's authorization for exploitation phases.
  const nextDraftable = useMemo(() => {
    if (!selected) return null
    const current = selected.current_phase || 'recon'
    const analyzed = new Set(selected.analyzed_phases || [])
    if (current === 'vuln_analysis' && analyzed.has('recon')) return 'exploitation'
    if (current === 'post_exploitation' && analyzed.has('exploitation')) return 'post_exploitation'
    return null
  }, [selected])

  const draftPhase = phase => run('planner', async () => {
    const id = selected.id
    const d = await request(`/assessments/${id}/phases/${phase}/plan`, { method: 'POST' })
    await reloadAssessment(id)
    await refresh()
    pushFeed(`Drafted ${d.drafted_steps} ${PHASE_LABEL(phase)} steps for assessment #${id}. Nothing runs until you approve it.`, 'ok')
    setNotice(`Drafted ${d.drafted_steps} ${PHASE_LABEL(phase)} step${d.drafted_steps !== 1 ? 's' : ''} from the analysis — review each one, then approve it when you're ready.`)
  })

  // Ask what to do next, given what has actually been observed. This proposes
  // and nothing else: candidates land in the panel for the operator to pick
  // from, and accepting them goes through the ordinary Save plan path, so the
  // policy checks and the immutability rules apply to them identically.
  const proposeNextSteps = () => run('planner', async () => {
    const id = selected.id
    const data = await request(`/assessments/${id}/next-steps`, { method: 'POST' })
    setNextProposals(data)
    setPickedCandidates(new Set())
    const refused = data.refused.length ? `, ${data.refused.length} refused by the policy engine` : ''
    pushFeed(`Proposed ${data.candidates.length} next step${data.candidates.length !== 1 ? 's' : ''} for assessment #${id}${refused}. Nothing runs until you approve it.`, data.candidates.length ? 'ok' : '')
  })

  const addPickedCandidates = () => {
    if (!nextProposals || !pickedCandidates.size) return
    const chosen = nextProposals.candidates.filter((_, index) => pickedCandidates.has(index))
    setDraftPlan(plan => [...plan, ...chosen])
    setNextProposals(null)
    setPickedCandidates(new Set())
    pushFeed(`Added ${chosen.length} proposed step${chosen.length !== 1 ? 's' : ''} to the plan for assessment #${selected.id}. Save the plan so approvals run them.`, 'ok')
    setNotice(`Added ${chosen.length} proposed step${chosen.length !== 1 ? 's' : ''} to the plan — review and edit them, then save the plan.`)
  }

  // Everything below is view state for the run being inspected: clearing the
  // workspace or one assessment must drop it all, or the panels would keep
  // describing an assessment the backend no longer has.
  const forgetAssessment = () => { clearAssessment(); setReportUrl(''); setNextProposals(null); setPickedCandidates(new Set()) }
  const deleteAssessment = id => {
    if (!window.confirm(`Delete assessment #${id} with its executions, findings and report? This cannot be undone.`)) return
    run('', async () => {
      await request(`/assessments/${id}`, { method: 'DELETE' })
      if (selected?.id === id) forgetAssessment()
      await refresh()
      pushFeed(`Deleted assessment #${id}.`)
      setNotice(`Assessment #${id} deleted.`)
    })
  }
  // The persisted database is why every reload showed the last engagement's
  // results: assessments survive across sessions until they are explicitly
  // removed. This is the fresh board between two letters or two demos; the
  // provider and VM configuration stays because it describes the operator's
  // setup, not the engagement.
  const resetWorkspace = () => {
    if (!window.confirm('Clear the whole workspace? Every registered target, assessment, execution, finding and report is permanently deleted. Your provider and VM configuration is kept.')) return
    run('', async () => {
      const d = await request('/workspace/reset', { method: 'POST' })
      forgetAssessment()
      setBrief(null); setBriefFilename(''); setBriefText('')
      setAssessment({ target_id: '', objective: '', requirements: '' }); setRequirementFile(null)
      setPromptTargetIds([]); setPromptText(''); setFeed([])
      await refresh()
      pushFeed(`Cleared the workspace — ${d.deleted.assessments} assessment${d.deleted.assessments !== 1 ? 's' : ''} and ${d.deleted.targets} target${d.deleted.targets !== 1 ? 's' : ''} removed.`, 'ok')
      setNotice('Workspace cleared — ready for a new engagement letter.')
    })
  }

  // The agent crew the cards animate. `working` comes from the live request
  // lifecycle (`activeAgent`); `done` reads saved state only, so a card never
  // claims an agent finished work the backend has not recorded.
  const crew = useMemo(() => {
    const findings = selected?.finding_count || 0
    const planned = !!selected && (selected.plan || []).length > 0
    const current = selected?.current_phase || 'recon'
    const analyzed = new Set(selected?.analyzed_phases || [])
    return [
      { key: 'reader', emoji: '📄', name: 'Brief reader', idle: 'Waiting for the client letter', working: 'Reading the letter…', done: !!brief, doneText: briefFilename ? `Read “${briefFilename}”` : '' },
      { key: 'registrar', emoji: '🗂️', name: 'Registrar', idle: 'Registers authorized targets', working: 'Registering targets…', done: targets.length > 0, doneText: targets.length ? `${targets.length} target${targets.length !== 1 ? 's' : ''} on file` : '' },
      { key: 'planner', emoji: '🧭', name: 'Planner', idle: 'Drafts commands for your approval', working: 'Drafting the command plan…', done: planned, doneText: planned ? `${(selected.plan || []).length} steps awaiting approval` : '' },
      { key: 'executor', emoji: '⚡', name: 'Executor', idle: 'Runs only what you approve', working: 'Running the approved command…', done: completedSteps.length > 0, doneText: completedSteps.length ? `${completedSteps.length}/${enabledSteps.length} commands complete` : '' },
      { key: 'exploiter', emoji: '🎯', name: 'Exploiter', idle: 'Verifies findings when the letter allows', working: 'Planning controlled verification…', done: analyzed.has('exploitation'), doneText: analyzed.has('exploitation') ? 'Findings verified' : current === 'exploitation' ? 'Exploitation phase active' : '' },
      { key: 'analyst', emoji: '🔎', name: 'Analyst', idle: 'Correlates and scores findings', working: 'Correlating outputs…', done: selected?.status === 'analyzed' || selected?.status === 'reported', doneText: findings ? `${findings} finding${findings !== 1 ? 's' : ''} scored` : '' },
      { key: 'reporter', emoji: '📝', name: 'Reporter', idle: 'Writes the client report', working: 'Writing the report…', done: selected?.status === 'reported', doneText: selected?.status === 'reported' ? 'Report ready to download' : '' },
    ]
  }, [brief, briefFilename, targets, selected, completedSteps, enabledSteps])

  useEffect(() => {
    if (!planDirty) return
    const warn = event => { event.preventDefault(); event.returnValue = '' }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [planDirty])
  const lock = () => { setOperatorKey(''); setApiKey(''); setKeyInput(''); setKeyPrompt(true); forgetAssessment(); setTargets([]); setAssessments([]); setSettings({}); setFeed([]) }
  const navigateAssessment = id => {
    if (planDirty && !window.confirm('Discard unsaved plan edits?')) return
    setNextProposals(null); setPickedCandidates(new Set()); setReportUrl(''); setTab('Overview'); openAssessment(id)
  }
  const app = { request, run, pushFeed, busy, activeAgent, agentBusy, notice, setNotice }

  if (keyPrompt) return <ApiKeyGate keyInput={keyInput} setKeyInput={setKeyInput} onSave={saveApiKey} remember={rememberKey} setRemember={setRememberKey} />
  if (loading) return <main className="loading-screen"><div className="loading-mark" /><p>Loading control center...</p></main>

  return <AppContext.Provider value={app}>
    <main>
      {busy && <div className="busy-bar" aria-hidden="true" />}
      {!backendUp && <div className="offline-banner">⚠ Cannot reach the backend at <code>{API}</code> — buttons will not respond until the stack is running again.</div>}
      <header><div><span className="eyebrow">AUTHORIZED SECURITY ORCHESTRATION</span><h1>Red Team Control Center</h1><p>Hand me the client's letter — I'll draft the plan, and every command waits for your approval.</p></div><div className="header-actions"><span className="health"><i /> Authorized workspace</span><button className="secondary compact" onClick={lock}>Lock workspace</button></div></header>
      {notice && <div className="notice" role="status">{notice}<button aria-label="Dismiss notification" onClick={() => setNotice('')}>×</button></div>}
      <section className="stats"><div><b>{targets.length}</b><span>Authorized targets</span></div><div><b>{assessments.length}</b><span>Assessments</span></div><div><b>{assessments.filter(a => a.status === 'reported').length}</b><span>Reports completed</span></div><div><b>{settings.provider_ready ? 'AI' : 'Local'}</b><span>Configured analyzer</span></div></section>

      <nav className="workspace-nav" aria-label="Workspace">{['Assessments', 'Targets', 'Settings'].map(name => <button key={name} aria-current={page === name ? 'page' : undefined} className={page === name ? 'active' : 'secondary'} onClick={() => setPage(name)}>{name}</button>)}</nav>
      {page === 'Settings' && <div className="settings-layout"><ConfigurationPanel settings={settings} setSettings={setSettings} sshTest={sshTest} onSave={saveSettings} onTestSsh={testSshConnection} /></div>}
      {page === 'Targets' && <div className="settings-layout"><TargetPanel target={target} setTarget={setTarget} onAdd={addTarget} />{targets.map(t => <section className="panel" key={t.id}><h2>{t.name}</h2><code>{t.scope_domain_ip}</code><p>Authorized scopes: {t.authorized_scopes.join(', ')}</p><ScopePolicy value={t.engagement_policy || {}} readOnly /></section>)}</div>}
      {page === 'Assessments' && <div className="workspace">
        <aside>
          <NewAssessmentPanel targets={targets} brief={brief} briefFilename={briefFilename} mode={assessmentMode} setMode={setAssessmentMode} assessment={assessment} setAssessment={setAssessment} setRequirementFile={setRequirementFile} promptTargetIds={promptTargetIds} togglePromptTarget={togglePromptTarget} promptText={promptText} setPromptText={setPromptText} onCreateFromLetter={createAssessment} onCreateFromPrompt={createFromPrompt} />
          <AssessmentsPanel assessments={assessments} targets={targets} selected={selected} onOpen={navigateAssessment} onDelete={deleteAssessment} onReset={resetWorkspace} />
          <div className="pagination"><button className="secondary" disabled={!catalogPage} onClick={() => setCatalogPage(p => p - 1)}>Previous</button><span>{catalogPage + 1} / {Math.max(1, Math.ceil(catalogTotal / 30))}</span><button className="secondary" disabled={(catalogPage + 1) * 30 >= catalogTotal} onClick={() => setCatalogPage(p => p + 1)}>Next</button></div>
        </aside>
        <section className="main-column">
          {!selected && <section className="panel onboarding"><span className="eyebrow">START AN ASSESSMENT</span><h2>Define the scope. Review the plan. Run with approval.</h2><p>Import a client letter below, review its rules, and create an assessment. You can also register a target in Targets and write an objective.</p></section>}
          {(!selected || tab === 'Overview') && <><LetterPanel brief={brief} briefFilename={briefFilename} targets={targets} onClear={() => { setBrief(null); setBriefFilename(''); setBriefText('') }} onImport={importBrief} onRegisterTarget={registerBriefTarget} onSetup={setupFromBrief} />{brief && <section className="panel"><h2>Review enforceable engagement rules</h2><p>Translate the letter?s exclusions and dates into these fields before registering targets. Prose restrictions still require your review.</p><ScopePolicy value={reviewedPolicy} onChange={setReviewedPolicy} /></section>}</>}
          {selected && <>
            <div className="assessment-heading"><div><span className="eyebrow">ASSESSMENT #{selected.id} ? PLAN v{selected.plan_version}</span><h2>{selectedTarget?.name}</h2><p>{selected.objective}</p></div><span className="tag">{selected.status.replaceAll('_', ' ')}</span></div>
            <nav className="assessment-tabs" aria-label="Assessment sections">{['Overview', 'Plan', 'Findings', 'Activity', 'Report'].map(name => <button key={name} aria-current={tab === name ? 'page' : undefined} className={tab === name ? 'active' : 'secondary'} onClick={() => setTab(name)}>{name}{name === 'Findings' ? ` (${selected.finding_count || 0})` : ''}</button>)}</nav>
            {planDirty && <div className="notice" role="status">Unsaved plan changes <button className="secondary compact" onClick={savePlan} disabled={busy || !planEditable}>Save plan</button></div>}
            {runningStep !== null && <div className="run-banner" role="status">Step {runningStep + 1} {liveExec?.state || 'queued'} ? {liveElapsed}s <button className="secondary compact" onClick={() => setTab('Plan')}>View output</button><button className="danger compact" onClick={cancelExecution}>Cancel execution</button></div>}
            {tab === 'Overview' && <PhasePipeline selected={selected} selectedTarget={selectedTarget} phases={phases} nextDraftable={nextDraftable} currentPhase={currentPhase} nextProposals={nextProposals} pickedCandidates={pickedCandidates} setPickedCandidates={setPickedCandidates} planEditable={planEditable} onDraftPhase={draftPhase} onPropose={proposeNextSteps} onDismissProposals={() => { setNextProposals(null); setPickedCandidates(new Set()) }} onAddPicked={addPickedCandidates} />}
            {tab === 'Plan' && <PlanEditor selected={selected} selectedTarget={selectedTarget} draftPlan={draftPlan} setDraftPlan={setDraftPlan} executionByStep={executionByStep} runningStep={runningStep} liveExec={liveExec} liveElapsed={liveElapsed} planLocked={planLocked} planEditable={planEditable} planDirty={planDirty} capabilities={capabilities} toolNames={toolNames} onSave={savePlan} onExecute={execute} />}
            {(tab === 'Overview' || tab === 'Report') && <AnalysisPanel selected={selected} currentPhase={currentPhase} phaseSteps={phaseSteps} phaseCompleted={phaseCompleted} planDirty={planDirty} canAnalyze={canAnalyze} canReport={canReport} reportUrl={reportUrl} onAnalyze={analyze} onReport={report} onDownloadReport={downloadReport} />}
            {tab === 'Findings' && <FindingsPanel key={selected.id} assessment={selected} assessments={assessments} />}
            {tab === 'Activity' && <><CrewPanel crew={crew} activeAgent={activeAgent} feed={feed} onClearFeed={() => setFeed([])} /><AuditTrailPanel assessmentId={selected.id} executions={selected.executions} /></>}
            {tab === 'Report' && <ReportVersions assessmentId={selected.id} status={selected.status} />}
          </>}
        </section>
      </div>}
      <footer>For authorized laboratory environments only · Human approval required before every command</footer>
    </main>
  </AppContext.Provider>
}
export default App
