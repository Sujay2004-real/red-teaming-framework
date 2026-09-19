import { useCallback, useEffect, useRef, useState } from 'react'

export function useAssessment(request, onError) {
  const [selected, setSelected] = useState(null)
  const [draftPlan, setDraftPlan] = useState([])
  const current = useRef(null)
  const pending = useRef(null)
  const errorRef = useRef(onError)
  useEffect(() => { errorRef.current = onError }, [onError])
  const load = useCallback(async (id, select = true) => {
    if (!select && current.current !== id) return
    pending.current?.abort()
    const controller = new AbortController()
    pending.current = controller
    if (select) current.current = id
    try {
      const data = await request(`/assessments/${id}/snapshot`, { signal: controller.signal })
      if (controller.signal.aborted || current.current !== id) return
      setSelected(data)
      setDraftPlan(data.plan || [])
    } catch (error) {
      if (!controller.signal.aborted) errorRef.current(error.message)
    }
  }, [request])
  useEffect(() => () => pending.current?.abort(), [])
  const clear = () => { pending.current?.abort(); current.current = null; setSelected(null); setDraftPlan([]) }
  return { selected, draftPlan, setDraftPlan, openAssessment: load,
    reloadAssessment: id => load(id, false), clearAssessment: clear }
}
