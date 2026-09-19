import { useEffect, useRef } from 'react'

export function useRecommendations(id, request, onBatch) {
  const callback = useRef(onBatch)
  useEffect(() => { callback.current = onBatch }, [onBatch])
  useEffect(() => {
    if (!id) return
    const controller = new AbortController()
    let timer, newest = 0
    const tick = async () => {
      try {
        const data = await request(`/assessments/${id}/recommendations`, { signal: controller.signal })
        if (controller.signal.aborted) return
        const batch = data.recommendations?.[0]
        if (batch && batch.id > newest) { newest = batch.id; callback.current(batch) }
      } catch { /* Health banner handles transport outages; retry without overlap. */ }
      if (!controller.signal.aborted) timer = setTimeout(tick, 4000)
    }
    tick()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [id, request])
}
