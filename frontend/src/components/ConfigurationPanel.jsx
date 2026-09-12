import { useApp } from '../lib/AppContext'

// Provider / proxy / execution-engine configuration. Secrets are write-only:
// the form blanks them after a save and shows only whether one is stored.
export default function ConfigurationPanel({ settings, setSettings, sshTest, onSave, onTestSsh }) {
  const { busy } = useApp()
  return <section className="panel">
    <div className="panel-title">
      <h2>Configuration</h2>
      <span className={settings.provider_ready ? 'tag good' : 'tag'}>{settings.provider_ready ? 'AI provider ready' : 'Fallback mode'}</span>
      <span className={settings.execution_mode === 'kali_vm' ? 'tag good' : 'tag'}>{settings.execution_mode === 'kali_vm' ? 'Kali VM engine' : 'Local engine'}</span>
    </div>
    <form onSubmit={onSave}>
      <div className="provider-fields">
        <label>Base URL<input type="url" placeholder="https://your-provider.example/v1" value={settings.api_base_url || ''} onChange={e => setSettings({ ...settings, api_base_url: e.target.value })} /><small>Your own OpenAI-compatible endpoint. No provider is assumed.</small></label>
        <label>Model name<input placeholder="your-model-name" value={settings.model_name || ''} onChange={e => setSettings({ ...settings, model_name: e.target.value })} /></label>
        <label>API key<input type="password" placeholder={settings.gemini_configured ? 'Configured ••••••••' : 'Enter your own API key'} value={settings.gemini_api_key} onChange={e => setSettings({ ...settings, gemini_api_key: e.target.value })} /><small>{settings.gemini_configured ? 'Leave blank to keep the stored key.' : 'Encrypted before storage and never returned by the API.'}</small></label>
      </div>
      <small className="plan-note">All three are needed for AI planning and analysis. Leave them blank to run entirely on the local deterministic analyzer.</small>
      <label>HTTP/S proxy<input placeholder="http://proxy:8080" value={settings.proxy_url || ''} onChange={e => setSettings({ ...settings, proxy_url: e.target.value })} /><small>Clearing this also clears the credentials below.</small></label>
      <div className="split">
        <label>Username<input value={settings.proxy_username || ''} onChange={e => setSettings({ ...settings, proxy_username: e.target.value })} /></label>
        <label>Password<input type="password" placeholder={settings.proxy_password_configured ? 'Configured ••••••••' : 'Proxy password'} value={settings.proxy_password || ''} onChange={e => setSettings({ ...settings, proxy_password: e.target.value })} /><small>{settings.proxy_password_configured ? 'Leave blank to keep the stored password.' : 'Encrypted before storage and never returned by the API.'}</small></label>
      </div>
      <small className="plan-note">Execution engine — where the commands you approve physically run.</small>
      <label>Execution mode<select value={settings.execution_mode || 'local'} onChange={e => setSettings({ ...settings, execution_mode: e.target.value })}><option value="local">Local / Docker container</option><option value="kali_vm">Kali VM over SSH (attacker VM)</option></select><small>VM mode types every approved command into the Kali VM's tmux session and records the VM's identity with each run. On the VM console, run <code>tmux attach -t redteam</code> to watch it live.</small></label>
      {settings.execution_mode === 'kali_vm' && <>
        <div className="split"><label>VM host<input placeholder="192.168.56.15" value={settings.ssh_host || ''} onChange={e => setSettings({ ...settings, ssh_host: e.target.value })} /><small>Host-only adapter address of your Kali VM.</small></label><label>SSH port<input type="number" min="1" max="65535" value={settings.ssh_port || 22} onChange={e => setSettings({ ...settings, ssh_port: e.target.value })} /></label></div>
        <div className="split"><label>Username<input placeholder="root" value={settings.ssh_username || ''} onChange={e => setSettings({ ...settings, ssh_username: e.target.value })} /></label><label>Password<input type="password" placeholder={settings.ssh_password_configured ? 'Configured ••••••••' : 'VM password'} value={settings.ssh_password || ''} onChange={e => setSettings({ ...settings, ssh_password: e.target.value })} /><small>{settings.ssh_password_configured ? 'Leave blank to keep the stored password.' : 'Encrypted before storage and never returned by the API.'}</small></label></div>
        <button type="button" className="secondary" onClick={onTestSsh} disabled={busy}>{busy ? 'Working…' : 'Test connection'}</button>
        {sshTest && <div className="ssh-attest">
          <b>Attacker VM verified</b>
          <p>{sshTest.user}@{sshTest.host}{sshTest.hostname ? ` · ${sshTest.hostname}` : ''}</p>
          <p>{sshTest.os} · kernel {sshTest.kernel}</p>
          <p className="mono">SSH host key {sshTest.host_key_fingerprint}</p>
          <p className="tool-check">{sshTest.tmux_ok ? '✓ tmux' : '✗ tmux missing'}{(Object.keys(sshTest.tools || {})).map(name => sshTest.tools[name] && sshTest.tools[name] !== 'MISSING' ? ` ✓ ${name}` : ` ✗ ${name}`)}</p>
          {sshTest.install_hint && <small>Missing in the VM — run: <code>{sshTest.install_hint}</code></small>}
        </div>}
      </>}
      <button className="secondary" disabled={busy}>{busy ? 'Saving…' : 'Save configuration'}</button><small>Responses never return secret values.</small>
    </form>
  </section>
}
