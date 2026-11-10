import { expect, test } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ObjectiveEvidence from './ObjectiveEvidence'

const criterion = {
  kind: 'sql_injection', label: 'Confirm SQL injection', endpoint: 'http://lab.test/products?id=1',
  parameter: 'id', status: 'achieved', reason: 'Confirmed by successful, analyzed scanner output.',
  evidence: [{ execution_id: 12, attempt: 2, tool: 'sqlmap', excerpt: "GET parameter 'id' is injectable", evidence_sha256: 'a'.repeat(64) }],
}

test('objective evidence exposes the actual execution, attempt and digest', async () => {
  render(<ObjectiveEvidence result={{ status: 'achieved', criteria: [criterion], scope_note: 'Only the declared endpoint was assessed.' }} />)
  await userEvent.click(screen.getByText('Execution #12, attempt 2 · sqlmap'))
  expect(screen.getByText("GET parameter 'id' is injectable")).toBeVisible()
  expect(screen.getByText('a'.repeat(64))).toBeVisible()
  expect(screen.getByText('Only the declared endpoint was assessed.')).toBeInTheDocument()
})

test('a negative or failed check does not display an achieved verdict', () => {
  const { rerender } = render(<ObjectiveEvidence result={{ status: 'not_demonstrated', criteria: [{ ...criterion, status: 'not_demonstrated', evidence: [], reason: 'No confirming evidence.' }] }} />)
  expect(screen.queryByText('Achieved')).not.toBeInTheDocument()
  expect(screen.getAllByText('Not demonstrated')).toHaveLength(2)
  rerender(<ObjectiveEvidence result={{ status: 'inconclusive', criteria: [{ ...criterion, status: 'inconclusive', evidence: [], reason: 'The scanner timed out.' }] }} />)
  expect(screen.queryByText('Achieved')).not.toBeInTheDocument()
  expect(screen.getByText('The scanner timed out.')).toBeInTheDocument()
})

test('changing to an assessment without criteria removes the prior proof', () => {
  const { rerender } = render(<ObjectiveEvidence result={{ status: 'achieved', criteria: [criterion] }} />)
  rerender(<ObjectiveEvidence result={{ status: 'not_configured', criteria: [] }} />)
  expect(screen.queryByRole('region', { name: 'Campaign objective evidence' })).not.toBeInTheDocument()
  expect(screen.queryByText(/Execution #12/)).not.toBeInTheDocument()
})
