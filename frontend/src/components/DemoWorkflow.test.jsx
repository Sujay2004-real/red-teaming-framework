import { afterEach, expect, test, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import App from '../App'
import { AppContext } from '../lib/AppContext'
import { setOperatorKey, KEY_STORAGE } from '../lib/api'
import NewAssessmentPanel from './NewAssessmentPanel'
import CommandCard from './CommandCard'

afterEach(() => { setOperatorKey(''); vi.unstubAllGlobals() })
const response = (data, status = 200) => Promise.resolve({ ok: status < 400, status, json: async () => data })

test('a rejected operator key remains on the gate, can be retried, and is never persisted', async () => {
  const user = userEvent.setup()
  setOperatorKey('')
  vi.stubGlobal('fetch', vi.fn((url, options) => {
    if (url.endsWith('/health')) return response({ status: 'ok' })
    if (options?.headers?.['X-API-Key'] !== 'valid-key') return response({}, 401)
    if (url.includes('/catalog/')) return response({ items: [], total: 60, reported_total: 42 })
    if (url.endsWith('/targets/')) return response([])
    if (url.endsWith('/capabilities')) return response([])
    return response({ provider_ready: false })
  }))
  render(<App />)
  const key = await screen.findByLabelText('Operator API key')
  await user.type(key, 'wrong-key')
  await user.click(screen.getByRole('button', { name: 'Unlock' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('This key was not accepted')
  expect(key).toHaveValue('wrong-key')
  expect(localStorage.getItem(KEY_STORAGE)).toBeNull()
  await user.clear(key); await user.type(key, 'valid-key')
  await user.click(screen.getByRole('button', { name: 'Unlock' }))
  const stats = await screen.findByRole('region', { name: 'Workspace totals' })
  expect(within(stats).getByText('60')).toBeInTheDocument()
  expect(within(stats).getByText('42')).toBeInTheDocument()
  expect(localStorage.getItem(KEY_STORAGE)).toBeNull()
})

test('the selected assessment and next action come before the collapsed letter panel', async () => {
  const user = userEvent.setup()
  setOperatorKey('valid-key')
  const assessment = { id: 3, target_id: 1, objective: 'Review security headers', status: 'awaiting_approval', plan_version: 1, current_phase: 'recon', analyzed_phases: [], plan: [{ tool: 'curl', command: 'curl -I http://lab.test', enabled: true }], executions: [], finding_count: 0 }
  vi.stubGlobal('fetch', vi.fn(url => {
    if (url.endsWith('/targets/')) return response([{ id: 1, name: 'Demo lab', scope_domain_ip: 'lab.test', authorized_scopes: ['lab.test'] }])
    if (url.includes('/catalog/')) return response({ items: [assessment], total: 1, reported_total: 0 })
    if (url.endsWith('/snapshot')) return response(assessment)
    if (url.includes('/recommendations')) return response({ recommendations: [] })
    if (url.endsWith('/capabilities')) return response([])
    return response({ provider_ready: false })
  }))
  render(<App />)
  await user.click(await screen.findByRole('button', { name: /#3.*Demo lab/ }))
  const heading = await screen.findByRole('heading', { name: 'Demo lab' })
  expect(screen.getByRole('button', { name: 'Review command plan' })).toBeEnabled()
  expect(screen.getByText('1 step awaiting your approval')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Review command plan' }).compareDocumentPosition(document.querySelector('.pipeline')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  const letter = document.querySelector('.brief-panel')
  expect(letter).not.toHaveAttribute('open')
  expect(heading.compareDocumentPosition(letter) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  expect(screen.getAllByText('Not authorized', { selector: '.stage-label' })[0].closest('li')).toHaveClass('blocked')
})

test('requirements attachment stays visible, rejects unsupported replacements, and can be removed', async () => {
  const user = userEvent.setup({ applyAccept: false })
  const notice = vi.fn()
  function Form() {
    const [file, setFile] = useState(null)
    return <NewAssessmentPanel targets={[{ id: 1, name: 'Lab' }]} mode="letter" assessment={{ target_id: '1', objective: '', requirements: '' }} requirementFile={file} setRequirementFile={setFile} />
  }
  render(<AppContext.Provider value={{ busy: false, agentBusy: () => false, setNotice: notice }}><Form /></AppContext.Provider>)
  const input = screen.getByLabelText(/Client requirements/)
  await user.upload(input, new File(['Scope'], 'requirements.pdf', { type: 'application/pdf' }))
  expect(screen.getByRole('status')).toHaveTextContent('requirements.pdf')
  await user.upload(input, new File(['Bad'], 'bad.exe'))
  expect(notice).toHaveBeenCalledWith(expect.stringContaining('Use a PDF'))
  expect(screen.getByRole('status')).toHaveTextContent('requirements.pdf')
  await user.click(screen.getByRole('button', { name: 'Remove requirements attachment' }))
  expect(screen.queryByRole('status')).toBeNull()
})

test('completed command output loads on expansion and failed commands remain eligible for reapproval', async () => {
  const user = userEvent.setup()
  const request = vi.fn(async () => ({ stdout: 'Recorded output', stderr: 'Tool failed' }))
  const execute = vi.fn()
  render(<AppContext.Provider value={{ request, setNotice: vi.fn() }}><CommandCard index={0} step={{ tool: 'curl', command: 'curl -I http://lab.test' }} execution={{ id: 4, complete: true, state: 'failed', return_code: 1, attempt: 1, retryable: true }} assessmentId={3} capabilities={[]} toolNames={new Set(['curl'])} currentPhase="recon" saved onExecute={execute} /></AppContext.Provider>)
  expect(request).not.toHaveBeenCalled()
  await user.click(screen.getByRole('button', { name: 'Show recorded output' }))
  expect(await screen.findByText(/Recorded output/)).toBeInTheDocument()
  expect(request.mock.calls[0][0]).toBe('/assessments/3/executions/4/evidence')
  await user.click(screen.getByRole('button', { name: 'Re-approve & retry' }))
  expect(execute).toHaveBeenCalledOnce()
  await user.click(screen.getByRole('button', { name: 'Hide recorded output' }))
  expect(screen.queryByText(/Recorded output/)).toBeNull()
})

test('generating a report offers an explicit open link without relying on an automatic popup', async () => {
  const user = userEvent.setup()
  setOperatorKey('valid-key')
  const popup = vi.spyOn(window, 'open').mockImplementation(() => null)
  const OriginalURL = URL
  vi.stubGlobal('URL', class extends OriginalURL {
    static createObjectURL() { return 'blob:generated-report' }
    static revokeObjectURL() {}
  })
  let reported = false
  const assessment = () => ({ id: 3, target_id: 1, objective: 'Inspect', status: reported ? 'reported' : 'analyzed', current_phase: 'reporting', plan_version: 1, plan: [], executions: [], analyzed_phases: ['recon'], finding_count: 0 })
  vi.stubGlobal('fetch', vi.fn((url, options) => {
    if (url.endsWith('/targets/')) return response([{ id: 1, name: 'Lab', scope_domain_ip: 'lab.test' }])
    if (url.includes('/catalog/')) return response({ items: [assessment()], total: 1, reported_total: reported ? 1 : 0 })
    if (url.endsWith('/snapshot')) return response(assessment())
    if (url.endsWith('/report') && options?.method === 'POST') { reported = true; return response({ download_url: '/assessments/3/reports/5' }) }
    if (url.endsWith('/reports/5')) return Promise.resolve({ ok: true, blob: async () => new Blob(['Report'], { type: 'text/html' }) })
    if (url.endsWith('/reports') || url.endsWith('/capabilities')) return response([])
    if (url.includes('/recommendations')) return response({ recommendations: [] })
    return response({ provider_ready: false })
  }))
  render(<App />)
  await user.click(await screen.findByRole('button', { name: /#3.*Lab/ }))
  await user.click(await screen.findByRole('button', { name: 'Open reporting' }))
  await user.click(screen.getByRole('button', { name: 'Generate report' }))
  expect(await screen.findByRole('link', { name: 'Open generated report' })).toHaveAttribute('href', 'blob:generated-report')
  expect(popup).not.toHaveBeenCalled()
  popup.mockRestore()
})

test('a command added during exploitation can be saved in the active phase', async () => {
  const user = userEvent.setup()
  setOperatorKey('valid-key')
  const assessment = { id: 3, target_id: 1, objective: 'Verify findings', status: 'awaiting_approval', current_phase: 'exploitation', plan_version: 1, plan: [], executions: [], analyzed_phases: ['recon'], finding_count: 1 }
  vi.stubGlobal('fetch', vi.fn((url, options) => {
    if (url.endsWith('/targets/')) return response([{ id: 1, name: 'Lab', scope_domain_ip: 'lab.test', exploitation_authorized: true }])
    if (url.includes('/catalog/')) return response({ items: [assessment], total: 1, reported_total: 0 })
    if (url.endsWith('/snapshot')) return response(assessment)
    if (url.endsWith('/plan') && options?.method === 'PUT') {
      const plan = JSON.parse(options.body).plan
      if (plan.some(step => step.phase !== 'exploitation')) return response({ detail: 'Wrong phase for the new command' }, 422)
      assessment.plan = plan
      return response({})
    }
    if (url.endsWith('/capabilities')) return response([{ id: 'tools', tools: [{ name: 'curl' }] }])
    if (url.includes('/recommendations')) return response({ recommendations: [] })
    return response({ provider_ready: false })
  }))
  render(<App />)
  await user.click(await screen.findByRole('button', { name: /#3.*Lab/ }))
  await user.click(await screen.findByRole('button', { name: 'Review command plan' }))
  await user.click(screen.getByRole('button', { name: 'Add command' }))
  await user.type(screen.getByLabelText('Command for step 1'), 'curl -I http://lab.test')
  await user.click(screen.getByRole('button', { name: 'Save plan' }))
  expect(await screen.findByText('Command plan saved and ready for individual approval.')).toBeInTheDocument()
})
