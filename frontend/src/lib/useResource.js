import { useEffect, useState } from 'react'

export function useResource(request, path, version = 0, { keepPreviousData = false } = {}) {
  const [result, setResult] = useState({ path: '', version: null, data: null, error: '' })
  useEffect(() => {
    if (!path) return
    const controller = new AbortController()
    request(path, { signal: controller.signal }).then(data => {
      if (!controller.signal.aborted) setResult({ path, version, data, error: '' })
    }).catch(error => {
      if (!controller.signal.aborted) setResult({ path, version, data: null, error: error.message })
    })
    return () => controller.abort()
  }, [request, path, version])
  const isLoading = !!path && (result.path !== path || result.version !== version)
  if (!path) return { data: null, error: '', isLoading: false }
  return isLoading ? { data: keepPreviousData ? result.data : null, error: '', isLoading: true } : { ...result, isLoading: false }
}
