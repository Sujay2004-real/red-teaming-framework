import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [targets, setTargets] = useState([])
  const [newTarget, setNewTarget] = useState({ name: '', scope_domain_ip: '' })
  const [assessments, setAssessments] = useState([])
  const [newAssessment, setNewAssessment] = useState({ target_id: '', objective: '' })

  const API_URL = 'http://localhost:8000'

  useEffect(() => {
    fetchTargets()
    fetchAssessments()
  }, [])

  const fetchTargets = async () => {
    try {
      const res = await fetch(`${API_URL}/targets/`)
      const data = await res.json()
      setTargets(data)
    } catch (e) { console.error(e) }
  }

  const fetchAssessments = async () => {
    try {
      const res = await fetch(`${API_URL}/assessments/`)
      const data = await res.json()
      setAssessments(data)
    } catch (e) { console.error(e) }
  }

  const addTarget = async (e) => {
    e.preventDefault()
    try {
      await fetch(`${API_URL}/targets/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newTarget)
      })
      setNewTarget({ name: '', scope_domain_ip: '' })
      fetchTargets()
    } catch (e) { console.error(e) }
  }

  const createAssessment = async (e) => {
    e.preventDefault()
    try {
      await fetch(`${API_URL}/assessments/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...newAssessment, target_id: parseInt(newAssessment.target_id) })
      })
      setNewAssessment({ target_id: '', objective: '' })
      fetchAssessments()
    } catch (e) { console.error(e) }
  }

  return (
    <div className="App" style={{ padding: '20px', fontFamily: 'sans-serif' }}>
      <h1>AI Semi-Autonomous Red Teaming Framework</h1>
      
      <div style={{ display: 'flex', gap: '40px' }}>
        <div style={{ flex: 1, border: '1px solid #ccc', padding: '20px', borderRadius: '8px' }}>
          <h2>Targets</h2>
          <form onSubmit={addTarget} style={{ marginBottom: '20px' }}>
            <input 
              placeholder="Name (e.g. Local DVWA)" 
              value={newTarget.name} 
              onChange={e => setNewTarget({...newTarget, name: e.target.value})} 
              required 
            />
            <input 
              placeholder="IP / Domain (e.g. 192.168.1.100)" 
              value={newTarget.scope_domain_ip} 
              onChange={e => setNewTarget({...newTarget, scope_domain_ip: e.target.value})} 
              required 
            />
            <button type="submit">Add Target</button>
          </form>
          
          <ul>
            {targets.map(t => (
              <li key={t.id}>{t.name} ({t.scope_domain_ip})</li>
            ))}
          </ul>
        </div>

        <div style={{ flex: 1, border: '1px solid #ccc', padding: '20px', borderRadius: '8px' }}>
          <h2>Assessments</h2>
          <form onSubmit={createAssessment} style={{ marginBottom: '20px' }}>
            <select 
              value={newAssessment.target_id} 
              onChange={e => setNewAssessment({...newAssessment, target_id: e.target.value})} 
              required
            >
              <option value="">Select Target...</option>
              {targets.map(t => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            <input 
              placeholder="Objective (e.g. Find XSS vulnerabilities)" 
              value={newAssessment.objective} 
              onChange={e => setNewAssessment({...newAssessment, objective: e.target.value})} 
              required 
            />
            <button type="submit">Create Assessment</button>
          </form>
          
          <ul>
            {assessments.map(a => (
              <li key={a.id} style={{ marginBottom: '15px', borderBottom: '1px solid #eee', paddingBottom: '10px' }}>
                <strong>Assessment #{a.id}</strong> (Target ID: {a.target_id})<br/>
                <em>Objective:</em> {a.objective}<br/>
                <em>Status:</em> {a.status}<br/>
                <em>Plan:</em> 
                {a.plan && (
                  <pre style={{ background: '#f4f4f4', padding: '10px', fontSize: '12px' }}>
                    {JSON.stringify(a.plan, null, 2)}
                  </pre>
                )}
                {/* Normally we would add buttons here to trigger execute_step, analyze, and report */}
                <button onClick={() => alert("Execution requires calling /execute API for each step. UI logic pending.")}>
                  Run Next Step
                </button>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

export default App
