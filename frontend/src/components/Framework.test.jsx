import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { AppContext } from '../lib/AppContext'
import ScenarioLibrary from './ScenarioLibrary'
import WorkflowPanel from './WorkflowPanel'
import CommandCard from './CommandCard'

const scenario = { id: 'web', version: '1.0.0', name: 'Web checks', description: 'Review application responses', inputs: { url: { label: 'Application URL', type: 'url' } }, steps: [{ id: 'headers' }] }
const target = { id: 1, name: 'App', scope_domain_ip: 'http://app.test' }
const step = { tool: 'curl', command: 'curl -I http://app.test', reason: 'Inspect headers', phase: 'recon', scenario_node: 'headers' }
function wrapper(request, children) {
  return <AppContext.Provider value={{ request, busy: false, setNotice: vi.fn() }}>{children}</AppContext.Provider>
}

test('scenario inputs require a fresh preview before creating a campaign', async () => {
  const request = vi.fn(async path => path.startsWith('/framework/scenarios') ? { items: [scenario], total: 1 } : path === '/framework/preview' ? { plan: [step] } : { id: 8 })
  const created = vi.fn()
  render(wrapper(request, <ScenarioLibrary targets={[target]} onCreated={created} />))
  const user = userEvent.setup()
  await user.click(await screen.findByRole('button', { name: /Web checks/ }))
  await user.selectOptions(screen.getByLabelText('Authorized target'), '1')
  await user.type(screen.getByLabelText('Application URL'), 'http://app.test')
  await user.click(screen.getByRole('button', { name: 'Review scenario plan' }))
  expect(await screen.findByRole('button', { name: 'Create campaign' })).toBeEnabled()
  await user.type(screen.getByLabelText('Application URL'), '/health')
  expect(screen.queryByRole('button', { name: 'Create campaign' })).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Review scenario plan' }))
  await user.click(await screen.findByRole('button', { name: 'Create campaign' }))
  await waitFor(() => expect(created).toHaveBeenCalledWith(8))
  const call = request.mock.calls.find(([path]) => path === '/framework/assessments')
  expect(JSON.parse(call[1].body).bindings.url).toBe('http://app.test/health')
})

test('workflow controls carry the server revision and show errors', async () => {
  const request = vi.fn(async path => {
    if (path.includes('/framework/events')) return { items: [] }
    if (path.endsWith('/control')) throw new Error('Assessment changed; reload')
    return { workflow_revision: 7, control: 'active', nodes: [], cleanup: [], detection: { items: [], total: 0, evaluated: 0, alerted: 0 } }
  })
  render(wrapper(request, <WorkflowPanel assessment={{ id: 1 }} onChanged={vi.fn()} onRetest={vi.fn()} />))
  const user = userEvent.setup()
  expect(await screen.findByRole('button', { name: 'Pause and cancel active work' })).toBeDisabled()
  await user.type(screen.getByLabelText('Control note'), 'Maintenance')
  await user.click(screen.getByRole('button', { name: 'Pause and cancel active work' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Assessment changed')
  expect(JSON.parse(request.mock.calls.find(([path]) => path.endsWith('/control'))[1].body).workflow_revision).toBe(7)
})

test('a scenario branch cannot be approved or edited while waiting', () => {
  render(wrapper(vi.fn(), <CommandCard index={0} step={step} capabilities={[]} toolNames={new Set(['curl'])} saved currentPhase="recon" scenarioLocked workflowNode={{ status: 'waiting', reason: 'Waiting for prerequisite' }} onExecute={vi.fn()} />))
  expect(screen.getByRole('button', { name: 'Approve & execute' })).toBeDisabled()
  expect(screen.getByLabelText('Command for step 1')).toBeDisabled()
  expect(screen.getByText('Waiting for prerequisite')).toBeInTheDocument()
})
