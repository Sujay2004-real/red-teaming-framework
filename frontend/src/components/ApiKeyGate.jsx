// The operator API key prompt: shown only after the backend answers 401, so
// it never blocks a first-load health check and never covers the UI when a
// valid key is already stored.
import Icon from './Icon'

export default function ApiKeyGate({ keyInput, setKeyInput, onSave, remember = false, setRemember, error = '', busy = false, backendUp }) {
  return <div className="key-gate">
    <form onSubmit={onSave} aria-label="Unlock workspace">
      <span className="gate-mark"><Icon name="shield" /></span>
      <span className="eyebrow">RED TEAM CONTROL CENTER</span>
      <h1>Unlock your workspace</h1>
      <p>Enter your operator key to access authorized assessments, evidence, and reports.</p>
      {backendUp === false && <p className="inline-error" role="status">Backend offline. Start the backend, then try again.</p>}
      {error && <p className="inline-error" id="key-error" role="alert">{error}</p>}
      <div className="key-row">
        <input aria-label="Operator API key" aria-describedby={error ? 'key-error' : undefined} aria-invalid={!!error} type="password" autoComplete="off" placeholder="Paste the operator API key" value={keyInput} onChange={e => setKeyInput(e.target.value)} disabled={busy} autoFocus />
        <button type="submit" disabled={busy || !keyInput.trim()}>{busy ? 'Checking…' : 'Unlock'}<Icon name="arrow" /></button>
      </div>
      <label className="check-row"><input type="checkbox" checked={remember} disabled={busy} onChange={e => setRemember(e.target.checked)} /> Remember this key on this device</label><small>Leave unchecked to keep the key for this session. Find the key in the backend console or your configured REDTEAM_API_KEY.</small>
    </form>
  </div>
}
