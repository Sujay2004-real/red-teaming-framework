import { useEffect, useMemo, useState } from 'react'
import './App.css'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const emptyStep = () => ({ tool: 'nmap', command: '', reason: '', enabled: true })

function App() {
  const [targets, setTargets] = useState([]), [assessments, setAssessments] = useState([])
  const [selected, setSelected] = useState(null), [notice, setNotice] = useState(''), [busy, setBusy] = useState(false)
  const [target, setTarget] = useState({ name: '', scope_domain_ip: '', authorized_scopes: '' })
  const [assessment, setAssessment] = useState({ target_id: '', objective: '', requirements: '' })
  const [requirementFile, setRequirementFile] = useState(null)
  const [settings, setSettings] = useState({ gemini_api_key: '', api_base_url: 'https://api.openai.com/v1', model_name: 'gpt-4o-mini', proxy_url: '', proxy_username: '', proxy_password: '', gemini_configured: false })
  const [loading, setLoading] = useState(true)

  const request = async (path, options={}) => {
    const res = await fetch(API + path, { headers: {'Content-Type':'application/json'}, ...options })
    const data = await res.json().catch(()=>({}))
    if (!res.ok) throw new Error(data.detail || 'Request failed')
    return data
  }
  const refresh = async () => {
    const [t,a,s] = await Promise.all([request('/targets/'), request('/assessments/'), request('/settings')])
    setTargets(t); setAssessments(a); setSettings(v => ({...v,...s}))
  }
  const openAssessment = async id => {
    try { setSelected(await request(`/assessments/${id}`)) }
    catch (e) { setNotice(e.message) }
  }
  /* eslint-disable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */
  useEffect(()=>{ refresh().catch(e=>setNotice(e.message)).finally(()=>setLoading(false)) },[])
  /* eslint-enable react-hooks/set-state-in-effect, react-hooks/exhaustive-deps */
  const run = async fn => { setBusy(true); setNotice(''); try { await fn() } catch(e){ setNotice(e.message) } finally { setBusy(false) } }
  const saveSettings = e => run(async()=>{ e.preventDefault(); await request('/settings',{method:'PUT',body:JSON.stringify(settings)}); setSettings(v=>({...v,gemini_api_key:'',proxy_password:''})); await refresh(); setNotice('Settings saved. Secrets are masked after storage.') })
  const addTarget = e => run(async()=>{ e.preventDefault(); await request('/targets/',{method:'POST',body:JSON.stringify({...target,authorized_scopes:target.authorized_scopes.split(',').map(x=>x.trim()).filter(Boolean)})}); setTarget({name:'',scope_domain_ip:'',authorized_scopes:''}); await refresh() })
  const createAssessment = e => run(async()=>{ e.preventDefault(); let requirements=assessment.requirements; if(requirementFile){ const form=new FormData(); form.append('file', requirementFile); const extracted=await fetch(API+'/requirements/extract',{method:'POST',body:form}); const data=await extracted.json(); if(!extracted.ok) throw new Error(data.detail||'Could not read requirements'); requirements=data.text } const a=await request('/assessments/',{method:'POST',body:JSON.stringify({...assessment,target_id:Number(assessment.target_id),requirements})}); setAssessment({target_id:'',objective:'',requirements:''}); setRequirementFile(null); await refresh(); await openAssessment(a.id) })
  const savePlan = () => run(async()=>{ await request(`/assessments/${selected.id}/plan`,{method:'PUT',body:JSON.stringify({plan:selected.plan})}); await openAssessment(selected.id); setNotice('Command plan saved and ready for individual approval.') })
  const execute = index => run(async()=>{ await request(`/assessments/${selected.id}/execute`,{method:'POST',body:JSON.stringify({step_index:index,approved:true})}); await openAssessment(selected.id); await refresh() })
  const analyze = () => run(async()=>{ await request(`/assessments/${selected.id}/analyze`,{method:'POST'}); await openAssessment(selected.id); await refresh() })
  const report = () => run(async()=>{ const d=await request(`/assessments/${selected.id}/report`,{method:'POST'}); window.open(API+d.download_url,'_blank'); await openAssessment(selected.id); await refresh() })
  const patchStep = (i,key,value) => setSelected(v=>({...v,plan:v.plan.map((s,n)=>n===i?{...s,[key]:value}:s)}))
  const executionByStep = useMemo(() => new Map((selected?.executions || []).map(execution => [execution.step_index, execution])), [selected])
  const enabledSteps = useMemo(() => (selected?.plan || []).map((step, index) => ({ step, index })).filter(({step}) => step.enabled !== false), [selected])
  const completedSteps = useMemo(() => enabledSteps.filter(({index}) => executionByStep.get(index)?.return_code !== null && executionByStep.get(index)?.return_code !== undefined), [enabledSteps, executionByStep])
  const planDirty = !!selected?.plan?.some((step, index) => {
    const execution = executionByStep.get(index)
    return execution && (execution.command !== step.command || execution.tool_name !== step.tool)
  })
  const canAnalyze = !!selected && enabledSteps.length > 0 && completedSteps.length === enabledSteps.length
  const canReport = selected?.status === 'analyzed' || selected?.status === 'reported'

  if (loading) return <main className="loading-screen"><div className="loading-mark"/><p>Loading control center...</p></main>

  return <main>
    <header><div><span className="eyebrow">AUTHORIZED SECURITY ORCHESTRATION</span><h1>Red Team Control Center</h1><p>Plan, approve, execute, correlate, and report—with every decision visible.</p></div><div className="health"><i/> Lab environment</div></header>
    {notice && <div className="notice">{notice}<button onClick={()=>setNotice('')}>×</button></div>}
    <section className="stats"><div><b>{targets.length}</b><span>Authorized targets</span></div><div><b>{assessments.length}</b><span>Assessments</span></div><div><b>{assessments.filter(a=>a.status==='reported').length}</b><span>Reports completed</span></div><div><b>{settings.gemini_configured?'AI':'Local'}</b><span>Configured analyzer</span></div></section>

    <div className="workspace">
      <aside>
        <section className="panel"><div className="panel-title"><h2>Configuration</h2><span className={settings.gemini_configured?'tag good':'tag'}>{settings.gemini_configured?'AI provider ready':'Fallback mode'}</span></div><form onSubmit={saveSettings}>
          <div className="provider-fields"><label>Base URL<input type="url" required placeholder="https://api.openai.com/v1" value={settings.api_base_url||''} onChange={e=>setSettings({...settings,api_base_url:e.target.value})}/><small>OpenAI-compatible API endpoint</small></label><label>Model name<input required placeholder="gpt-4o-mini" value={settings.model_name||''} onChange={e=>setSettings({...settings,model_name:e.target.value})}/></label><label>API key<input type="password" placeholder={settings.gemini_configured?'Configured ••••••••':'Enter your API key'} value={settings.gemini_api_key} onChange={e=>setSettings({...settings,gemini_api_key:e.target.value})}/></label></div>
          <label>HTTP/S proxy<input placeholder="http://proxy:8080" value={settings.proxy_url||''} onChange={e=>setSettings({...settings,proxy_url:e.target.value})}/></label>
          <div className="split"><label>Username<input value={settings.proxy_username||''} onChange={e=>setSettings({...settings,proxy_username:e.target.value})}/></label><label>Password<input type="password" value={settings.proxy_password||''} onChange={e=>setSettings({...settings,proxy_password:e.target.value})}/></label></div>
          <button className="secondary" disabled={busy}>Save configuration</button><small>Stored locally for this prototype. Responses never return secret values.</small>
        </form></section>
        <section className="panel"><h2>Add authorized target</h2><form onSubmit={addTarget}><label>Display name<input required value={target.name} onChange={e=>setTarget({...target,name:e.target.value})} placeholder="Juice Shop lab"/></label><label>Primary host<input required value={target.scope_domain_ip} onChange={e=>setTarget({...target,scope_domain_ip:e.target.value})} placeholder="juice-shop:3000"/></label><label>Allowed domains / CIDRs<input value={target.authorized_scopes} onChange={e=>setTarget({...target,authorized_scopes:e.target.value})} placeholder="juice-shop, 172.18.0.0/16"/></label><button disabled={busy}>Add target</button></form></section>
        <section className="panel"><h2>New assessment</h2><form onSubmit={createAssessment}><label>Target<select required value={assessment.target_id} onChange={e=>setAssessment({...assessment,target_id:e.target.value})}><option value="">Select target</option>{targets.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}</select></label><label>Objective<textarea required value={assessment.objective} onChange={e=>setAssessment({...assessment,objective:e.target.value})} placeholder="Identify high-risk web vulnerabilities before release"/></label><label>Client requirements<input type="file" accept=".txt,.md,.pdf,.docx" onChange={e=>setRequirementFile(e.target.files?.[0]||null)}/><small>Optional planning context; every command still needs HITL approval.</small></label><button disabled={busy}>Generate command plan</button></form></section>
      </aside>

      <section className="main-column">
        <section className="panel"><div className="panel-title"><h2>Assessments</h2><span className="muted">Select a run to inspect</span></div><div className="assessment-list">{assessments.length===0?<div className="empty">Create your first authorized assessment.</div>:assessments.map(a=><button key={a.id} className={`assessment-row ${selected?.id===a.id?'active':''}`} onClick={()=>openAssessment(a.id)}><span><b>#{a.id} · {targets.find(t=>t.id===a.target_id)?.name||'Target'}</b><small>{a.objective}</small></span><span className={`status ${a.status}`}>{a.status.replaceAll('_',' ')}</span></button>)}</div></section>

        {selected && <>
          <section className="panel"><div className="panel-title"><div><span className="eyebrow">ASSESSMENT #{selected.id}</span><h2>Editable command plan</h2></div><button className="secondary compact" onClick={savePlan} disabled={busy||selected.executions?.length}>Save plan</button></div><p className="muted intro">Review every command before execution. Enabled steps require approval and pass policy checks.</p>
            <div className="plan">{selected.plan.map((step,i)=>{ const execution=executionByStep.get(i); const complete=execution?.return_code !== null && execution?.return_code !== undefined; return <div className={`step ${step.enabled===false?'disabled-step':''}`} key={i}><div className="step-head"><span className="step-number">{i+1}</span><select value={step.tool} onChange={e=>patchStep(i,'tool',e.target.value)} disabled={!!execution}><option>nmap</option><option>traceroute</option><option>dig</option><option>nslookup</option><option>curl</option><option>whatweb</option><option>sslscan</option><option>nuclei</option></select><label className="toggle"><input type="checkbox" checked={step.enabled!==false} onChange={e=>patchStep(i,'enabled',e.target.checked)} disabled={!!execution}/><span/> Enabled</label><button className="icon-btn" title="Remove step" aria-label="Remove step" onClick={()=>setSelected(v=>({...v,plan:v.plan.filter((_,n)=>n!==i)}))} disabled={!!execution}>×</button></div><input className="command" value={step.command} onChange={e=>patchStep(i,'command',e.target.value)} disabled={!!execution}/><input value={step.reason||''} onChange={e=>patchStep(i,'reason',e.target.value)} placeholder="Why this command is needed" disabled={!!execution}/><div className="step-actions"><span className={complete?'step-complete':''}>{complete?'Execution logged':execution?'Execution in progress':'Awaiting explicit approval'}</span><button disabled={busy||step.enabled===false||!!execution||planDirty} onClick={()=>execute(i)}>{execution?'Executed':'Approve & execute'}</button></div></div>})}</div>
            <button className="secondary" onClick={()=>setSelected(v=>({...v,plan:[...v.plan,emptyStep()]}))} disabled={selected.executions?.length}>Add command</button>
            {selected.plan.length===0 && <div className="empty">Add at least one command to continue.</div>}
            {selected.executions?.length > 0 && <small className="plan-note">Execution has started, so this plan is locked.</small>}
          </section>

          <section className="panel action-panel"><div><h2>Analysis & report</h2><p>Correlates outputs, removes duplicate findings, and calculates transparent risk and priority scores.</p><span className="action-status">{canAnalyze?'All enabled steps complete':`${completedSteps.length}/${enabledSteps.length || 0} enabled steps complete`}</span></div><div><button className="secondary" onClick={analyze} disabled={busy||!canAnalyze}>Analyze results</button><button onClick={report} disabled={busy||!canReport}>Generate report</button></div></section>

          {!!selected.findings?.length && <section className="panel"><div className="panel-title"><h2>Prioritized findings</h2><span className="tag good">{selected.findings.length} correlated</span></div><div className="findings">{selected.findings.map(f=><article key={f.id}><div><span className={`severity ${f.severity}`}>{f.severity}</span><h3>{f.title}</h3><p>{f.description}</p></div><div className="scores"><span><b>{f.priority_score}</b>Priority</span><span><b>{f.risk_score}</b>Risk / 125</span><span><b>{f.confidence_score}%</b>Confidence</span></div><details><summary>Evidence and remediation</summary><pre>{f.evidence}</pre><p><b>Fix:</b> {f.remediation}</p></details></article>)}</div></section>}

          {!!selected.executions?.length && <section className="panel"><h2>Execution audit trail</h2><div className="audit">{selected.executions.map(e=><details key={e.id}><summary><b>{e.tool_name}</b><code>{e.command}</code><span className={e.return_code===0?'ok':'fail'}>exit {e.return_code} · {e.duration_ms} ms</span></summary><pre>{e.stdout||e.stderr||'No output returned.'}</pre></details>)}</div></section>}
        </>}
      </section>
    </div>
    <footer>For authorized laboratory environments only · Human approval required before every command</footer>
  </main>
}
export default App





