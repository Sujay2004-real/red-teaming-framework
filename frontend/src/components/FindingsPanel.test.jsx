import { expect, test, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import FindingsPanel from './FindingsPanel'
import { AppContext } from '../lib/AppContext'

test('evidence loads only when expanded and a review sends owner and retest evidence', async () => {
  const user = userEvent.setup()
  const finding = { id: 4, title: 'Missing header', severity: 'Low', endpoint: 'http://lab.test', source_tools: ['curl'], review: { status: 'open', owner: '', comments: [] } }
  const request = vi.fn(async (path, options) => {
    if (options?.method === 'PUT') return {}
    if (path.includes('?')) return { items: [finding], total: 1 }
    return { ...finding, evidence: 'HTTP/1.1 200 OK', remediation: 'Add the header' }
  })
  render(<AppContext.Provider value={{ request, run: (_agent, fn) => fn() }}><FindingsPanel assessment={{ id: 1, analyzed_phases: ['recon'] }} assessments={[]} /></AppContext.Provider>)
  expect(await screen.findByText('Missing header')).toBeInTheDocument()
  expect(request.mock.calls.every(([path]) => path.includes('?'))).toBe(true)
  await user.click(screen.getByRole('button', { name: 'Evidence and review' }))
  expect(await screen.findByText('HTTP/1.1 200 OK')).toBeInTheDocument()
  await user.type(screen.getByLabelText('Owner'), 'Operator')
  await user.selectOptions(screen.getByLabelText('Review status'), 'resolved')
  await user.type(screen.getByLabelText('Retest evidence'), 'Retest confirms the header')
  await user.click(screen.getByRole('button', { name: 'Save review' }))
  await waitFor(() => expect(request.mock.calls.some(([, options]) => options?.method === 'PUT')).toBe(true))
  const saved = request.mock.calls.find(([, options]) => options?.method === 'PUT')
  expect(JSON.parse(saved[1].body)).toMatchObject({ owner: 'Operator', status: 'resolved', retest_evidence: 'Retest confirms the header' })
})
