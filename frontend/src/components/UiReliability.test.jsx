import { useState } from 'react'
import { act, render, renderHook, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, test, vi } from 'vitest'
import App from '../App'
import { AppContext } from '../lib/AppContext'
import { setOperatorKey } from '../lib/api'
import { useAssessment } from '../lib/useAssessment'
import ScopePolicy from './ScopePolicy'
import CampaignPanel from './CampaignPanel'
import ConfigurationPanel from './ConfigurationPanel'

afterEach(() => { setOperatorKey(''); vi.unstubAllGlobals(); vi.restoreAllMocks() })
const response = data => Promise.resolve({ ok: true, status: 200, json: async () => structuredClone(data) })
const step = { tool: 'curl', command: 'curl -I http://lab.test', phase: 'recon', enabled: true }
const target = { id: 1, name: 'Lab', scope_domain_ip: 'lab.test', exploitation_authorized: false }
const baseAssessment = { id: 3, target_id: 1, objective: 'Inspect', status: 'reported', current_phase: 'reporting', plan_version: 1, plan: [], executions: [], analyzed_phases: ['recon'], finding_count: 0 }

function mockWorkspace(overrides = () => undefined) {
  setOperatorKey('test-key')
  const fetch = vi.fn((url, options) => {
    const special = overrides(url, options)
    if (special !== undefined) return special
    if (url.endsWith('/targets/')) return response([target])
    if (url.includes('/catalog/')) return response({ items: [baseAssessment], total: 1, reported_total: 1 })
    if (url.endsWith('/snapshot')) return response(baseAssessment)
    if (url.endsWith('/reports') || url.endsWith('/capabilities')) return response([])
    if (url.includes('/recommendations')) return response({ recommendations: [] })
    return response({ provider_ready: false, model_name: 'saved-model', execution_mode: 'local' })
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

test('snapshot refresh preserves unsaved edits and explicit save reload adopts the saved plan', async () => {
  let snapshot = { id: 1, plan: [step], executions: [] }
  const request = vi.fn(async () => structuredClone(snapshot))
  const { result } = renderHook(() => useAssessment(request, vi.fn()))
  await act(async () => { await result.current.openAssessment(1) })
  act(() => result.current.setDraftPlan(plan => [...plan, { ...step, reason: 'Unsaved new step' }]))
  snapshot = { ...snapshot, executions: [{ complete: true }], plan_version: 2 }
  await act(async () => { await result.current.reloadAssessment(1) })
  expect(result.current.selected.executions).toHaveLength(1)
  expect(result.current.draftPlan).toHaveLength(2)
  snapshot = { ...snapshot, plan: [{ ...step, reason: 'Server-confirmed plan' }] }
  await act(async () => { await result.current.reloadAssessment(1, { discardDraft: true }) })
  expect(result.current.draftPlan).toEqual(snapshot.plan)
})

test('a failed assessment switch leaves the visible assessment refreshable', async () => {
  const request = vi.fn().mockResolvedValueOnce({ id: 1, plan: [] })
    .mockRejectedValueOnce(new Error('Assessment unavailable'))
    .mockResolvedValueOnce({ id: 1, plan: [step] })
  const error = vi.fn()
  const { result } = renderHook(() => useAssessment(request, error))
  await act(async () => { await result.current.openAssessment(1) })
  await act(async () => { await result.current.openAssessment(2) })
  await act(async () => { await result.current.reloadAssessment(1) })
  expect(error).toHaveBeenCalledWith('Assessment unavailable')
  expect(result.current.selected.plan).toEqual([step])
})

test('operators can type and normalize multiple prohibited tools', async () => {
  function Form() {
    const [policy, setPolicy] = useState({})
    return <ScopePolicy value={policy} onChange={setPolicy} />
  }
  const user = userEvent.setup()
  render(<Form />)
  const input = screen.getByLabelText('Prohibited tools')
  await user.type(input, 'sqlmap, msfconsole, nuclei,')
  expect(input).toHaveValue('sqlmap, msfconsole, nuclei,')
  await user.tab()
  expect(input).toHaveValue('sqlmap,msfconsole,nuclei')
})

test('campaign action errors appear on the campaign page', async () => {
  const user = userEvent.setup()
  const campaign = { footholds: [], hosts: [], loot: [], autopilot: false, autopilot_iteration_budget: 5 }
  const request = vi.fn(path => path.endsWith('/campaign') ? Promise.resolve(campaign) : Promise.reject(new Error('Campaign is unavailable')))
  render(<AppContext.Provider value={{ request, pushFeed: vi.fn(), setNotice: vi.fn(), busy: false }}><CampaignPanel assessmentId={3} aggressive /></AppContext.Provider>)
  await user.click(await screen.findByRole('button', { name: 'Turn autopilot on' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Campaign is unavailable')
  expect(screen.getByRole('button', { name: 'Turn autopilot on' })).toBeEnabled()
})

test('an assessment without verification authorization offers reporting after analysis', async () => {
  mockWorkspace(url => url.endsWith('/snapshot') ? response({ ...baseAssessment, status: 'analyzed', current_phase: 'vuln_analysis' }) : undefined)
  const user = userEvent.setup()
  render(<App />)
  await user.click(await screen.findByRole('button', { name: /#3.*Lab/ }))
  expect(await screen.findByRole('button', { name: 'Open reporting' })).toBeEnabled()
  expect(screen.queryByRole('button', { name: 'Review policy response' })).not.toBeInTheDocument()
})

test('an already drafted campaign phase offers command review instead of drafting again', async () => {
  mockWorkspace(url => {
    if (url.endsWith('/targets/')) return response([{ ...target, aggressive_lab: true, exploitation_authorized: true }])
    if (url.endsWith('/snapshot')) return response({ ...baseAssessment, status: 'awaiting_approval', current_phase: 'credential_validation', plan: [{ ...step, phase: 'credential_validation' }] })
  })
  const user = userEvent.setup()
  render(<App />)
  await user.click(await screen.findByRole('button', { name: /#3.*Lab/ }))
  expect(await screen.findByRole('button', { name: 'Review command plan' })).toBeEnabled()
  expect(screen.queryByRole('button', { name: 'Draft next phase' })).not.toBeInTheDocument()
})

test('catalog refresh preserves unsaved configuration and displays the saved engine', async () => {
  mockWorkspace(url => url.includes('/catalog/') ? response({ items: [baseAssessment], total: 60, reported_total: 1 }) : undefined)
  const user = userEvent.setup()
  render(<App />)
  await user.click(await screen.findByRole('button', { name: 'Settings', exact: true }))
  await user.clear(screen.getByLabelText('Model name'))
  await user.type(screen.getByLabelText('Model name'), 'unsaved-model')
  await user.selectOptions(screen.getByLabelText(/^Execution mode/), 'kali_vm')
  expect(screen.getByText('Local execution engine')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Assessments', exact: true }))
  await user.click(screen.getByRole('button', { name: 'Next', exact: true }))
  await waitFor(() => expect(screen.getByText('2 / 2')).toBeInTheDocument())
  await user.click(screen.getByRole('button', { name: 'Settings', exact: true }))
  expect(screen.getByLabelText('Model name')).toHaveValue('unsaved-model')
  expect(screen.getByLabelText(/^Execution mode/)).toHaveValue('kali_vm')
})

test('connection tests respect native form validation and hide a fingerprint for another destination', async () => {
  const user = userEvent.setup()
  const testConnection = vi.fn()
  const request = vi.fn(async path => path.endsWith('ssh-fingerprint') ? { host: 'vm.test', port: 22, fingerprint: 'SHA256:test' } : {})
  function Form() {
    const [settings, setSettings] = useState({ execution_mode: 'kali_vm', ssh_host: 'vm.test', ssh_port: 22, ssh_username: 'operator' })
    return <ConfigurationPanel settings={settings} setSettings={setSettings} onTestSsh={testConnection} />
  }
  render(<AppContext.Provider value={{ request, run: (_agent, fn) => fn(), busy: false }}><Form /></AppContext.Provider>)
  await user.click(screen.getByRole('button', { name: 'Inspect host fingerprint' }))
  expect(await screen.findByRole('button', { name: 'Trust this fingerprint' })).toBeEnabled()
  await user.clear(screen.getByLabelText(/VM host/))
  await user.type(screen.getByLabelText(/VM host/), 'another.test')
  expect(screen.queryByRole('button', { name: 'Trust this fingerprint' })).not.toBeInTheDocument()
  await user.clear(screen.getByLabelText('SSH port'))
  await user.type(screen.getByLabelText('SSH port'), '70000')
  await user.click(screen.getByRole('button', { name: 'Test connection' }))
  expect(testConnection).not.toHaveBeenCalled()
})

test('regenerating reports refreshes history and creating an assessment clears the previous report', async () => {
  const user = userEvent.setup()
  let version = 0
  const OriginalURL = URL
  vi.stubGlobal('URL', class extends OriginalURL {
    static createObjectURL() { return `blob:report-${version}` }
    static revokeObjectURL() {}
  })
  const created = { ...baseAssessment, id: 4, status: 'awaiting_approval', current_phase: 'recon', plan: [step], analyzed_phases: [] }
  mockWorkspace((url, options) => {
    if (url.endsWith('/report')) { version++; return response({ download_url: '/reports/3' }) }
    if (url.endsWith('/reports/3')) return Promise.resolve({ ok: true, blob: async () => new Blob(['Report']) })
    if (url.endsWith('/reports')) return response(version ? [{ id: version, digest: 'hash', created_at: '2026-11-02T00:00:00Z' }] : [])
    if (url.endsWith('/assessments/') && options?.method === 'POST') return response(created)
    if (url.endsWith('/4/snapshot')) return response(created)
  })
  render(<App />)
  await user.click(await screen.findByRole('button', { name: /#3.*Lab/ }))
  await user.click(await screen.findByRole('button', { name: 'Open reporting' }))
  await user.click(screen.getByRole('button', { name: 'Generate report' }))
  expect(await screen.findByText('Version 1')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Generate report' }))
  expect(await screen.findByText('Version 2')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Open generated report' })).toHaveAttribute('href', 'blob:report-2')
  await user.click(screen.getByText('Create manually'))
  await user.selectOptions(screen.getByLabelText('Target', { exact: true }), '1')
  await user.type(screen.getByLabelText('Objective'), 'New assessment')
  await user.click(screen.getByRole('button', { name: 'Generate command plan' }))
  expect(await screen.findByText('ASSESSMENT #4 · PLAN v1')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Overview', exact: true })).toHaveAttribute('aria-current', 'page')
  await user.click(screen.getByRole('button', { name: 'Report', exact: true }))
  expect(screen.queryByRole('link', { name: 'Open generated report' })).not.toBeInTheDocument()
})
