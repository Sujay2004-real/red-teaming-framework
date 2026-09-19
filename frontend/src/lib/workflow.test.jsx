import { act, renderHook } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { createRequest, getOperatorKey, KEY_STORAGE, setOperatorKey } from './api'
import { useAssessment } from './useAssessment'
import { useExecution } from './useExecution'
import { useRecommendations } from './useRecommendations'

afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); setOperatorKey('') })
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r }); return { promise, resolve } }

test('operator key stays in memory unless persistence is chosen, and lock removes it', () => {
  setOperatorKey('memory-key')
  expect(getOperatorKey()).toBe('memory-key')
  expect(localStorage.getItem(KEY_STORAGE)).toBeNull()
  setOperatorKey('saved-key', true)
  expect(localStorage.getItem(KEY_STORAGE)).toBe('saved-key')
  setOperatorKey('')
  expect(localStorage.getItem(KEY_STORAGE)).toBeNull()
})

test('request cancellation forwards the caller signal and does not report a timeout', async () => {
  const caller = new AbortController()
  vi.stubGlobal('fetch', vi.fn((_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
  })))
  const request = createRequest(() => '', vi.fn())
  const pending = request('/test', { signal: caller.signal })
  caller.abort()
  await expect(pending).rejects.toHaveProperty('name', 'AbortError')
})

test('late assessment responses cannot replace the newly selected assessment', async () => {
  const first = deferred(), second = deferred()
  const request = vi.fn(path => path.includes('/1/') ? first.promise : second.promise)
  const { result } = renderHook(() => useAssessment(request, vi.fn()))
  act(() => { result.current.openAssessment(1); result.current.openAssessment(2) })
  await act(async () => { second.resolve({ id: 2, plan: [{ command: 'two' }] }); await second.promise })
  await act(async () => { first.resolve({ id: 1, plan: [{ command: 'one' }] }); await first.promise })
  expect(result.current.selected.id).toBe(2)
  expect(result.current.draftPlan[0].command).toBe('two')
})

test('reconnected execution consumes cursor deltas and reports completion', async () => {
  vi.useFakeTimers()
  const request = vi.fn().mockResolvedValueOnce({ output: 'first', cursor: 5, running: true, state: 'running' })
    .mockResolvedValueOnce({ output: ' second', cursor: 12, running: false, state: 'completed' })
  const completed = vi.fn()
  const selected = { id: 8, executions: [{ id: 12, step_index: 0, attempt: 1, complete: false }] }
  const { result } = renderHook(() => useExecution(selected, request, completed, vi.fn()))
  await act(async () => { await Promise.resolve() })
  expect(result.current.liveExec.output).toBe('first')
  await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
  expect(request.mock.calls[1][0]).toContain('cursor=5')
  expect(result.current.liveExec.output).toBe('first second')
  expect(completed).toHaveBeenCalledWith(8, 12)
})

test('recommendations from a previous assessment are ignored', async () => {
  const old = deferred(), next = deferred(), accept = vi.fn()
  const request = vi.fn(path => path.includes('/1/') ? old.promise : next.promise)
  const { rerender } = renderHook(({ id }) => useRecommendations(id, request, accept), { initialProps: { id: 1 } })
  rerender({ id: 2 })
  await act(async () => { old.resolve({ recommendations: [{ id: 4 }] }); await old.promise })
  expect(accept).not.toHaveBeenCalled()
  await act(async () => { next.resolve({ recommendations: [{ id: 5 }] }); await next.promise })
  expect(accept).toHaveBeenCalledWith({ id: 5 })
})
