// The operator API key prompt: shown only after the backend answers 401, so
// it never blocks a first-load health check and never covers the UI when a
// valid key is already stored.
export default function ApiKeyGate({ keyInput, setKeyInput, onSave, remember = false, setRemember }) {
  return <div className="key-gate">
    <form onSubmit={onSave} aria-label="Unlock workspace">
      <b>🔒 Operator API key required</b>
      <p>The backend refuses anonymous requests. The key was printed in the backend console on first start, or set via <code>REDTEAM_API_KEY</code>.</p>
      <div className="key-row">
        <input aria-label="Operator API key" type="password" placeholder="Paste the operator API key" value={keyInput} onChange={e => setKeyInput(e.target.value)} autoFocus />
        <button type="submit" disabled={!keyInput.trim()}>Unlock</button>
      </div>
      <label className="check-row"><input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} /> Remember this key on this device</label><small>Leave unchecked to keep the key only until this page closes. Lock removes any saved key.</small>
    </form>
  </div>
}
