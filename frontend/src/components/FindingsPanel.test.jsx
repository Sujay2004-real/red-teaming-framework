import { expect, test, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
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

test('search waits for typing and keeps findings visible until the new response arrives', async () => {
  const user = userEvent.setup()
  const finding = { id: 4, title: 'Missing header', severity: 'Low', source_tools: ['curl'], review: { status: 'open' } }
  let finishSearch
  const pending = new Promise(resolve => { finishSearch = resolve })
  const request = vi.fn(path => new URLSearchParams(path.split('?')[1]).get('search') ? pending : Promise.resolve({ items: [finding], total: 1 }))
  render(<AppContext.Provider value={{ request }}><FindingsPanel assessment={{ id: 1 }} assessments={[]} /></AppContext.Provider>)
  await screen.findByText('Missing header')
  await user.type(screen.getByLabelText('Search'), 'unknown')
  expect(screen.getByText('Missing header')).toBeInTheDocument()
  expect(screen.getByRole('status')).toHaveTextContent('Updating results')
  await waitFor(() => expect(request).toHaveBeenCalledTimes(2))
  expect(new URLSearchParams(request.mock.calls[1][0].split('?')[1]).get('search')).toBe('unknown')
  expect(screen.getByText('Missing header')).toBeInTheDocument()
  await act(async () => { finishSearch({ items: [], total: 0 }); await pending })
  expect(screen.getByText('No findings match your filters')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Reset filters' }))
  expect(await screen.findByText('Missing header')).toBeInTheDocument()
})

test('a failed findings request can be retried without losing the filters', async () => {
  const user = userEvent.setup()
  const request = vi.fn().mockRejectedValueOnce(new Error('Connection interrupted')).mockResolvedValue({ items: [], total: 0 })
  render(<AppContext.Provider value={{ request }}><FindingsPanel assessment={{ id: 1 }} assessments={[]} /></AppContext.Provider>)
  expect(await screen.findByRole('alert')).toHaveTextContent('Connection interrupted')
  await user.click(screen.getByRole('button', { name: 'Retry findings' }))
  expect(await screen.findByText('No findings yet')).toBeInTheDocument()
  expect(request.mock.calls[0][0]).toBe(request.mock.calls[1][0])
})
