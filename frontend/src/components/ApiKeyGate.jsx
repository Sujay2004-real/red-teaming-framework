// The operator API key prompt: shown only after the backend answers 401, so
// it never blocks a first-load health check and never covers the UI when a
// valid key is already stored.
export default function ApiKeyGate({ keyInput, setKeyInput, onSave }) {
  return <div className="key-gate">
    <form onSubmit={onSave}>
      <b>🔒 Operator API key required</b>
      <p>The backend refuses anonymous requests. The key was printed in the backend console on first start, or set via <code>REDTEAM_API_KEY</code>.</p>
      <div className="key-row">
        <input type="password" placeholder="Paste the operator API key" value={keyInput} onChange={e => setKeyInput(e.target.value)} autoFocus />
        <button type="submit" disabled={!keyInput.trim()}>Unlock</button>
      </div>
    </form>
  </div>
}
