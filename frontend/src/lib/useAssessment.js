import { useCallback, useEffect, useRef, useState } from 'react'
import { samePlan } from './constants'

export function useAssessment(request, onError) {
  const [workspace, setWorkspace] = useState({ selected: null, draftPlan: [] })
  const current = useRef(null)
  const loaded = useRef(null)
  const pending = useRef(null)
  const errorRef = useRef(onError)
  useEffect(() => { errorRef.current = onError }, [onError])
  const load = useCallback(async (id, select = true, { discardDraft = false } = {}) => {
    if (!select && current.current !== id) return
    pending.current?.abort()
    const controller = new AbortController()
    pending.current = controller
    if (select) current.current = id
    try {
      const data = await request(`/assessments/${id}/snapshot`, { signal: controller.signal })
      if (controller.signal.aborted || current.current !== id) return
      loaded.current = id
      setWorkspace(previous => ({
        selected: data,
        draftPlan: !select && !discardDraft && previous.selected?.id === id && !samePlan(previous.draftPlan, previous.selected.plan)
          ? previous.draftPlan : data.plan || [],
      }))
      return data
    } catch (error) {
      if (!controller.signal.aborted) {
        current.current = loaded.current
        errorRef.current(error.message)
      }
    }
  }, [request])
  useEffect(() => () => pending.current?.abort(), [])
  const setDraftPlan = update => setWorkspace(previous => ({ ...previous, draftPlan: typeof update === 'function' ? update(previous.draftPlan) : update }))
  const clear = () => { pending.current?.abort(); current.current = null; loaded.current = null; setWorkspace({ selected: null, draftPlan: [] }) }
  return { ...workspace, setDraftPlan, openAssessment: load,
    reloadAssessment: (id, options) => load(id, false, options), clearAssessment: clear }
}
