import { useEffect, useRef, useState } from 'react'
import { LIVE_POLL_MS } from './api'

export function useExecution(selected, request, onComplete, onError) {
  const [live, setLive] = useState(null)
  const callbacks = useRef({ onComplete, onError })
  useEffect(() => { callbacks.current = { onComplete, onError } }, [onComplete, onError])
  const active = selected?.executions?.find(e => !e.complete)
  const assessmentId = selected?.id, executionId = active?.id, attempt = active?.attempt
  useEffect(() => {
    if (!executionId) return
    const controller = new AbortController()
    let timer, cursor = 0, output = ''
    const tick = async () => {
      try {
        const data = await request(`/assessments/${assessmentId}/executions/${executionId}/live?cursor=${cursor}`, { signal: controller.signal })
        if (controller.signal.aborted) return
        output = (data.reset ? data.output : output + data.output).slice(-200000)
        cursor = data.cursor
        const elapsed = data.started_at ? Math.max(0, Math.floor((Date.now() - new Date(data.started_at + (/Z$|[+-]\d\d:\d\d$/.test(data.started_at) ? '' : 'Z'))) / 1000)) : 0
        setLive({ ...data, output, elapsed, assessmentId, id: executionId })
        if (!data.running) { callbacks.current.onComplete(assessmentId, executionId); return }
      } catch (error) {
        if (controller.signal.aborted) return
        callbacks.current.onError(error.message)
      }
      timer = setTimeout(tick, LIVE_POLL_MS)
    }
    tick()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [assessmentId, executionId, attempt, request])
  return { runningStep: active?.step_index ?? null,
    liveExec: live?.assessmentId === assessmentId && live?.id === executionId ? live : null,
    liveElapsed: live?.elapsed || 0 }
}
