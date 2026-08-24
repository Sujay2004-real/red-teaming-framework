import { useEffect, useMemo, useState } from 'react'
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
  'default-no-api-key': 'No AI provider is configured, so the built-in default plan was used.',
  'default-provider-error': 'The AI provider could not be reached, so the built-in default plan was used.',
  'default-policy-rejected': 'Every AI-suggested command failed policy review, so the built-in default plan was used.',
  user: 'Using the plan you supplied.',
}
const detailText = detail => Array.isArray(detail) ? detail.map(item => item?.msg || JSON.stringify(item)).join('; ') : typeof detail === 'string' ? detail : ''
const samePlan = (a, b) => JSON.stringify(a || []) === JSON.stringify(b || [])

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
  const [settings, setSettings] = useState({ gemini_api_key: '', api_base_url: 'https://api.openai.com/v1', model_name: 'gpt-4o-mini', proxy_url: '', proxy_username: '', proxy_password: '', gemini_configured: false })
  const [loading, setLoading] = useState(true)

  const request = async (path, options={}) => {
    const res = await fetch(API + path, { headers: {'Content-Type':'application/json'}, ...options })
    const data = await res.json().catch(()=>({}))
    if (!res.ok) throw new Error(detailText(data.detail) || `Request failed (${res.status})`)
    return data
  }
  const refresh = async () => {
    const [t,a,s,c] = await Promise.all([request('/targets/'), request('/assessments/'), request('/settings'), request('/capabilities').catch(()=>null)])
    setTargets(t); setAssessments(a); setSettings(v => ({...v,...s}))
    if (Array.isArray(c) && c.length) setCapabilities(c)
  }
  const openAssessment = async id => {
    try { const data = await request(`/assessments/${id}`); setSelected(data); setDraftPlan(data.plan || []) }
    catch (e) { setNotice(e.message) }
  }
  /* eslint-disable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */
  useEffect(()=>{ refresh().catch(e=>setNotice(e.message)).finally(()=>setLoading(false)) },[])
  /* eslint-enable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */
  const run = async fn => { setBusy(true); setNotice(''); try { await fn() } catch(e){ setNotice(e.message) } finally { setBusy(false) } }
  const saveSettings = e => run(async()=>{ e.preventDefault(); await request('/settings',{method:'PUT',body:JSON.stringify({gemini_api_key:settings.gemini_api_key||'',api_base_url:settings.api_base_url||'',model_name:settings.model_name||'',proxy_url:settings.proxy_url||'',proxy_username:settings.proxy_username||'',proxy_password:settings.proxy_password||''})}); setSettings(v=>({...v,gemini_api_key:'',proxy_password:''})); await refresh(); setNotice(settings.proxy_url ? 'Settings saved. Secrets are masked after storage.' : 'Settings saved. Clearing the proxy URL also cleared its stored credentials.') })
  const addTarget = e => run(async()=>{ e.preventDefault(); await request('/targets/',{method:'POST',body:JSON.stringify({...target,criticality:Math.min(100,Math.max(0,Number(target.criticality)||0)),authorized_scopes:target.authorized_scopes.split(',').map(x=>x.trim()).filter(Boolean)})}); setTarget({name:'',scope_domain_ip:'',authorized_scopes:'',criticality:70}); await refresh() })
  const createAssessment = e => run(async()=>{ e.preventDefault(); let requirements=assessment.requirements; if(requirementFile){ const form=new FormData(); form.append('file', requirementFile); const extracted=await fetch(API+'/requirements/extract',{method:'POST',body:form}); const data=await extracted.json().catch(()=>({})); if(!extracted.ok) throw new Error(detailText(data.detail)||'Could not read requirements'); requirements=data.text } const a=await request('/assessments/',{method:'POST',body:JSON.stringify({...assessment,target_id:Number(assessment.target_id),requirements})}); setAssessment({target_id:'',objective:'',requirements:''}); setRequirementFile(null); await refresh(); await openAssessment(a.id); setNotice(PLAN_SOURCE_NOTE[a.plan_source] || '') })
  const savePlan = () => run(async()=>{ await request(`/assessments/${selected.id}/plan`,{method:'PUT',body:JSON.stringify({plan:draftPlan})}); await openAssessment(selected.id); await refresh(); setNotice('Command plan saved and ready for individual approval.') })
  const execute = index => run(async()=>{ await request(`/assessments/${selected.id}/execute`,{method:'POST',body:JSON.stringify({step_index:index,approved:true})}); await openAssessment(selected.id); await refresh() })
  const analyze = () => run(async()=>{ const d=await request(`/assessments/${selected.id}/analyze`,{method:'POST'}); await openAssessment(selected.id); await refresh(); setNotice(d.failed_steps?.length ? `Analysis complete, but step ${d.failed_steps.map(i=>i+1).join(', ')} failed to run — findings may be incomplete.` : `Analysis complete (${d.analyzer}).`) })
  const report = () => run(async()=>{ const d=await request(`/assessments/${selected.id}/report`,{method:'POST'}); window.open(API+d.download_url,'_blank','noopener'); await openAssessment(selected.id); await refresh() })
  const patchStep = (i,key,value) => setDraftPlan(plan=>plan.map((s,n)=>n===i?{...s,[key]:value}:s))
  const toolNames = useMemo(() => new Set(capabilities.flatMap(group => (group.tools||[]).map(tool => tool.name))), [capabilities])
  const executionByStep = useMemo(() => new Map((selected?.executions || []).map(execution => [execution.step_index, execution])), [selected])
  // Gauges and the Analyze gate read the *saved* plan. Reading the draft let a
  // local "enabled" toggle light up Analyze while the backend still expected
  // the step to run, and the request then failed with a 409.
  const enabledSteps = useMemo(() => (selected?.plan || []).map((step, index) => ({ step, index })).filter(({step}) => step.enabled !== false), [selected])
  const completedSteps = useMemo(() => enabledSteps.filter(({index}) => executionByStep.get(index)?.complete), [enabledSteps, executionByStep])
  const planLocked = (selected?.executions?.length || 0) > 0
  const planDirty = !!selected && !samePlan(draftPlan, selected.plan)
  const canAnalyze = !!selected && !planDirty && enabledSteps.length > 0 && completedSteps.length === enabledSteps.length
  const canReport = selected?.status === 'analyzed' || selected?.status === 'reported'

  if (loading) return <main className="loading-screen"><div className="loading-mark"/><p>Loading control center...</p></main>

  return <main>
    <header><div><span className="eyebrow">AUTHORIZED SECURITY ORCHESTRATION</span><h1>Red Team Control Center</h1><p>Plan, approve, execute, correlate, and report—with every decision visible.</p></div><div className="health"><i/> Lab environment</div></header>
    {notice && <div className="notice">{notice}<button onClick={()=>setNotice('')}>×</button></div>}
    <section className="stats"><div><b>{targets.length}</b><span>Authorized targets</span></div><div><b>{assessments.length}</b><span>Assessments</span></div><div><b>{assessments.filter(a=>a.status==='reported').length}</b><span>Reports completed</span></div><div><b>{settings.gemini_configured?'AI':'Local'}</b><span>Configured analyzer</span></div></section>

    <div className="workspace">
      <aside>
        <section className="panel"><div className="panel-title"><h2>Configuration</h2><span className={settings.gemini_configured?'tag good':'tag'}>{settings.gemini_configured?'AI provider ready':'Fallback mode'}</span></div><form onSubmit={saveSettings}>
          <div className="provider-fields"><label>Base URL<input type="url" required placeholder="https://api.openai.com/v1" value={settings.api_base_url||''} onChange={e=>setSettings({...settings,api_base_url:e.target.value})}/><small>OpenAI-compatible API endpoint</small></label><label>Model name<input required placeholder="gpt-4o-mini" value={settings.model_name||''} onChange={e=>setSettings({...settings,model_name:e.target.value})}/></label><label>API key<input type="password" placeholder={settings.gemini_configured?'Configured ••••••••':'Enter your API key'} value={settings.gemini_api_key} onChange={e=>setSettings({...settings,gemini_api_key:e.target.value})}/><small>{settings.gemini_configured?'Leave blank to keep the stored key.':'Stored locally for this prototype.'}</small></label></div>
          <label>HTTP/S proxy<input placeholder="http://proxy:8080" value={settings.proxy_url||''} onChange={e=>setSettings({...settings,proxy_url:e.target.value})}/><small>Clearing this also clears the credentials below.</small></label>
          <div className="split"><label>Username<input value={settings.proxy_username||''} onChange={e=>setSettings({...settings,proxy_username:e.target.value})}/></label><label>Password<input type="password" value={settings.proxy_password||''} onChange={e=>setSettings({...settings,proxy_password:e.target.value})}/></label></div>
          <button className="secondary" disabled={busy}>Save configuration</button><small>Responses never return secret values.</small>
        </form></section>
        <section className="panel"><h2>Add authorized target</h2><form onSubmit={addTarget}><label>Display name<input required value={target.name} onChange={e=>setTarget({...target,name:e.target.value})} placeholder="Juice Shop lab"/></label><label>Primary host<input required value={target.scope_domain_ip} onChange={e=>setTarget({...target,scope_domain_ip:e.target.value})} placeholder="juice-shop:3000"/></label><label>Allowed domains / CIDRs<input value={target.authorized_scopes} onChange={e=>setTarget({...target,authorized_scopes:e.target.value})} placeholder="juice-shop, 172.18.0.0/16"/></label><label>Asset criticality<input type="number" min="0" max="100" required value={target.criticality} onChange={e=>setTarget({...target,criticality:e.target.value})}/><small>0-100. Feeds the priority score of every finding on this target.</small></label><button disabled={busy}>Add target</button></form></section>
        <section className="panel"><h2>New assessment</h2><form onSubmit={createAssessment}><label>Target<select required value={assessment.target_id} onChange={e=>setAssessment({...assessment,target_id:e.target.value})}><option value="">Select target</option>{targets.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}</select></label><label>Objective<textarea required value={assessment.objective} onChange={e=>setAssessment({...assessment,objective:e.target.value})} placeholder="Identify high-risk web vulnerabilities before release"/></label><label>Client requirements<input type="file" accept=".txt,.md,.pdf,.docx" onChange={e=>setRequirementFile(e.target.files?.[0]||null)}/><small>Optional planning context; every command still needs HITL approval.</small></label><button disabled={busy}>Generate command plan</button></form></section>
      </aside>

      <section className="main-column">
        <section className="panel"><div className="panel-title"><h2>Assessments</h2><span className="muted">Select a run to inspect</span></div><div className="assessment-list">{assessments.length===0?<div className="empty">Create your first authorized assessment.</div>:assessments.map(a=><button key={a.id} className={`assessment-row ${selected?.id===a.id?'active':''}`} onClick={()=>openAssessment(a.id)}><span><b>#{a.id} · {targets.find(t=>t.id===a.target_id)?.name||'Target'}</b><small>{a.objective}</small></span><span className={`status ${a.status}`}>{a.status.replaceAll('_',' ')}</span></button>)}</div></section>

        {selected && <>
          <section className="panel"><div className="panel-title"><div><span className="eyebrow">ASSESSMENT #{selected.id}</span><h2>Editable command plan</h2></div><button className="secondary compact" onClick={savePlan} disabled={busy||planLocked||!planDirty}>Save plan</button></div><p className="muted intro">Review every command before execution. Enabled steps require approval and pass policy checks.</p>
            <div className="plan">{draftPlan.map((step,i)=>{
              const execution = executionByStep.get(i)
              const running = !!execution && !execution.complete
              const executed = !!execution && execution.complete
              const retryable = !!execution?.retryable
              const savedStep = selected.plan?.[i]
              const locked = planLocked || running
              const label = running ? 'Running...' : retryable ? 'Re-approve & retry' : executed ? 'Executed' : 'Approve & execute'
              const state = running ? 'Execution in progress'
                : executed && execution.return_code === 0 ? `Execution logged${execution.attempt>1?` (attempt ${execution.attempt})`:''}`
                : executed ? `Did not succeed (exit ${execution.return_code}) after ${execution.attempt} attempt${execution.attempt>1?'s':''}`
                : planDirty ? 'Save the plan before approving'
                : 'Awaiting explicit approval'
              return <div className={`step ${step.enabled===false?'disabled-step':''}`} key={i}>
                <div className="step-head"><span className="step-number">{i+1}</span>
                  <select value={step.tool} onChange={e=>patchStep(i,'tool',e.target.value)} disabled={locked}>
                    {!toolNames.has(step.tool) && <option value={step.tool}>{step.tool} (not permitted)</option>}
                    {capabilities.map(group=><optgroup key={group.id} label={String(group.id).replaceAll('_',' ')}>{(group.tools||[]).map(tool=><option key={tool.name} value={tool.name}>{tool.name}</option>)}</optgroup>)}
                  </select>
                  <label className="toggle"><input type="checkbox" checked={step.enabled!==false} onChange={e=>patchStep(i,'enabled',e.target.checked)} disabled={locked}/><span/> Enabled</label>
                  <button className="icon-btn" title="Remove step" aria-label="Remove step" onClick={()=>setDraftPlan(plan=>plan.filter((_,n)=>n!==i))} disabled={locked}>×</button>
                </div>
                <input className="command" value={step.command} onChange={e=>patchStep(i,'command',e.target.value)} disabled={locked}/>
                <input value={step.reason||''} onChange={e=>patchStep(i,'reason',e.target.value)} placeholder="Why this command is needed" disabled={locked}/>
                <div className="step-actions"><span className={executed && execution.return_code===0?'step-complete':retryable?'step-failed':''}>{state}</span>
                  <button disabled={busy||step.enabled===false||running||(executed&&!retryable)||planDirty||!savedStep} onClick={()=>execute(i)}>{label}</button>
                </div>
              </div>})}</div>
            <button className="secondary" onClick={()=>setDraftPlan(plan=>[...plan,emptyStep(capabilities[0]?.tools?.[0]?.name)])} disabled={planLocked}>Add command</button>
            {draftPlan.length===0 && <div className="empty">Add at least one command to continue.</div>}
            {planLocked && <small className="plan-note">Execution has started, so this plan is locked. Failed or abandoned steps can still be re-approved individually.</small>}
            {!planLocked && planDirty && <small className="plan-note">Unsaved plan edits. Save the plan so approvals run the commands shown here.</small>}
          </section>

          <section className="panel action-panel"><div><h2>Analysis &amp; report</h2><p>Correlates outputs, removes duplicate findings, and calculates transparent risk and priority scores.</p><span className="action-status">{canAnalyze?'All enabled steps complete':`${completedSteps.length}/${enabledSteps.length || 0} enabled steps complete${planDirty?' · unsaved plan edits':''}`}</span></div><div><button className="secondary" onClick={analyze} disabled={busy||!canAnalyze}>Analyze results</button><button onClick={report} disabled={busy||!canReport}>Generate report</button>{selected.status==='reported' && <a className="download-link" href={`${API}/reports/${selected.id}`} target="_blank" rel="noreferrer">Download last report</a>}</div></section>

          {!!selected.findings?.length && <section className="panel"><div className="panel-title"><h2>Prioritized findings</h2><span className="tag good">{selected.findings.length} correlated</span></div><div className="findings">{selected.findings.map(f=><article key={f.id}><div><span className={`severity ${f.severity}`}>{f.severity}</span><h3>{f.title}</h3><p>{f.description}</p>{!!f.source_tools?.length && <small>Reported by {f.source_tools.join(', ')}</small>}</div><div className="scores"><span><b>{f.priority_score}</b>Priority</span><span><b>{f.risk_score}</b>Risk / 125</span><span><b>{f.confidence_score}%</b>Confidence</span></div><details><summary>Evidence and remediation</summary><pre>{f.evidence}</pre><p><b>Fix:</b> {f.remediation}</p></details></article>)}</div></section>}

          {!!selected.executions?.length && <section className="panel"><h2>Execution audit trail</h2><div className="audit">{selected.executions.map(e=><details key={e.id}><summary><b>{e.tool_name}</b><code>{e.command}</code><span className={!e.complete?'muted':e.return_code===0?'ok':'fail'}>{e.complete?`exit ${e.return_code} · ${e.duration_ms} ms`:'still running'}{e.attempt>1?` · attempt ${e.attempt}`:''}</span></summary><pre>{e.stdout||'No standard output returned.'}</pre>{!!e.stderr && <pre className="stderr">{e.stderr}</pre>}</details>)}</div></section>}
        </>}
      </section>
    </div>
    <footer>For authorized laboratory environments only · Human approval required before every command</footer>
  </main>
}
export default App
