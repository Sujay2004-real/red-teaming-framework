// The backend base URL and the operator-key plumbing every request needs.
// The key is entered once (the backend prints it on first start or takes it
// from REDTEAM_API_KEY), kept in localStorage only, and sent solely as the
// X-API-Key header to this backend — never anywhere else.

export const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'
export const KEY_STORAGE = 'rtcc-operator-key'

// Request budgets. The backend caps a scanner run at 360 s and AI provider
// calls at 60 s, so the browser gives up only after the server itself
// certainly has, and `busy` can never wedge on a request that never answers.
export const REQUEST_TIMEOUT_MS = 75_000
export const HEALTH_POLL_MS = 10_000
// How often the in-flight execution terminal polls the backend for new
// output while a command runs.
export const LIVE_POLL_MS = 1_000

export const loadStoredKey = () => {
  try { return localStorage.getItem(KEY_STORAGE) || '' } catch { return '' }
}

// The current operator key, held outside React so the request wrapper can
// read it at call time without re-creating itself on every key change.
let operatorKey = loadStoredKey()
export const getOperatorKey = () => operatorKey
export const setOperatorKey = (value, persist = false) => {
  operatorKey = value
  try { if (value && persist) localStorage.setItem(KEY_STORAGE, value); else localStorage.removeItem(KEY_STORAGE) } catch { /* private window; works until reload */ }
}

/**
 * Download a protected binary/HTML resource (the generated report) as an
 * object URL. Plain <a href> links cannot carry the X-API-Key header, so the
 * report is fetched with the key and handed to the browser as a blob instead.
 */
export const fetchProtectedObjectUrl = async (path, getKey) => {
  const apiKey = getKey()
  const res = await fetch(API + path, { headers: apiKey ? { 'X-API-Key': apiKey } : {} })
  if (!res.ok) throw new Error(`The download failed (${res.status}) — the report may not be generated yet.`)
  return URL.createObjectURL(await res.blob())
}

const detailText = detail => Array.isArray(detail)
  ? detail.map(item => item?.msg || JSON.stringify(item)).join('; ')
  : typeof detail === 'string' ? detail : ''

/**
 * Build the request function for the current operator key.
 *
 * `onUnauthorized` fires when the backend answers 401 — the fix is entering
 * the key, so the UI raises its key prompt instead of reporting a generic
 * failure.
 */
export const createRequest = (getKey, onUnauthorized) => async (path, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) => {
  const apiKey = getKey()
  // FormData bodies set their own multipart boundary; a JSON header on top
  // would corrupt the upload.
  const headers = options.body instanceof FormData
    ? {}
    : { 'Content-Type': 'application/json' }
  if (apiKey) headers['X-API-Key'] = apiKey
  const controller = new AbortController()
  const abort = () => controller.abort()
  if (options.signal?.aborted) controller.abort()
  options.signal?.addEventListener('abort', abort, { once: true })
  const timer = setTimeout(abort, timeoutMs)
  try {
    const res = await fetch(API + path, { headers, ...options, signal: controller.signal })
    if (res.status === 401) {
      onUnauthorized()
      throw new Error('The backend requires the operator API key — it was printed in the backend console on first start (or set REDTEAM_API_KEY). Enter it below.')
    }
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(detailText(data.detail) || `Request failed (${res.status})`)
    return data
  } catch (e) {
    // "TypeError: Failed to fetch" points at the code; the stopped
    // container is the actual cause. An abort is the timeout firing.
    if (options.signal?.aborted) throw e
    if (e.name === 'AbortError') throw new Error(`The backend did not answer within ${Math.round(timeoutMs / 1000)} seconds — it may be overloaded or restarting.`)
    if (e instanceof TypeError) throw new Error(`Cannot reach the backend at ${API} — is the stack running?`)
    throw e
  } finally {
    clearTimeout(timer)
    options.signal?.removeEventListener('abort', abort)
  }
}
