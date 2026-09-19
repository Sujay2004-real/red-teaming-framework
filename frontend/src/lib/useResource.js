import { useEffect, useState } from 'react'

export function useResource(request, path, version = 0) {
  const [result, setResult] = useState({ path: '', data: null, error: '' })
  useEffect(() => {
    if (!path) return
    const controller = new AbortController()
    request(path, { signal: controller.signal }).then(data => {
      if (!controller.signal.aborted) setResult({ path, data, error: '' })
    }).catch(error => {
      if (!controller.signal.aborted) setResult({ path, data: null, error: error.message })
    })
    return () => controller.abort()
  }, [request, path, version])
  return result.path === path ? result : { data: null, error: '' }
}
