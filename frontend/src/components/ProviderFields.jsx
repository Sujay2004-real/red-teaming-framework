import { PROVIDER_PRESETS, normalizeProviderUrl, providerSelection } from '../lib/providerPresets'

export default function ProviderFields({ settings, setSettings, savedProviderBaseUrl = '' }) {
  const selection = providerSelection(settings)
  const preset = PROVIDER_PRESETS.find(item => item.id === selection)
  const storedKeyMatches = settings.gemini_configured && normalizeProviderUrl(settings.api_base_url) === normalizeProviderUrl(savedProviderBaseUrl)
  const changeEndpoint = value => setSettings(current => ({
    ...current,
    provider_preset: 'custom',
    api_base_url: value,
    gemini_api_key: normalizeProviderUrl(value) === normalizeProviderUrl(current.api_base_url) ? current.gemini_api_key : '',
  }))
  const changeField = (field, value) => setSettings(current => ({
    ...current, provider_preset: preset ? undefined : 'custom', [field]: value,
  }))
  const chooseProvider = id => setSettings(current => {
    if (id === 'custom') return { ...current, provider_preset: 'custom' }
    const next = PROVIDER_PRESETS.find(item => item.id === id)
    const baseUrl = next?.baseUrl || ''
    return {
      ...current,
      provider_preset: id === 'local' ? 'local' : undefined,
      api_base_url: baseUrl,
      model_name: next?.model || '',
      gemini_api_key: next && normalizeProviderUrl(baseUrl) === normalizeProviderUrl(current.api_base_url) ? current.gemini_api_key : '',
    }
  })

  return <fieldset className="provider-fields config-section">
    <legend>AI provider</legend>
    <p className="muted">Choose a preset, paste your API key, and save. The model and endpoint are filled in for you.</p>
    <label htmlFor="provider-preset">Provider</label>
    <select id="provider-preset" value={selection} onChange={e => chooseProvider(e.target.value)}>
      <option value="local">Local only (no API key)</option>
      {PROVIDER_PRESETS.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
      <option value="custom">Custom / OpenAI-compatible</option>
    </select>
    {selection === 'local' ? <p className="provider-hint">The built-in planner and analyzer run locally. Saving this option disconnects the AI provider and removes its stored key.</p> : <>
      {preset && <div className="provider-hint provider-key-link">
        <span>{preset.help}</span>
        <a href={preset.keyUrl} target="_blank" rel="noopener noreferrer">Get an API key <span aria-hidden="true">↗</span></a>
      </div>}
      <label htmlFor="provider-api-key">API key</label>
      <input id="provider-api-key" type="password" autoComplete="off" spellCheck={false} maxLength={10000}
        required={!!preset && !storedKeyMatches} aria-describedby="provider-key-help"
        placeholder={storedKeyMatches ? 'Configured ••••••••' : 'Paste your API key'}
        value={settings.gemini_api_key || ''} onChange={e => changeField('gemini_api_key', e.target.value.trim())} />
      <small id="provider-key-help">{storedKeyMatches ? 'Leave blank to keep the stored key.' : settings.gemini_configured ? 'Enter a key for this endpoint. The previous provider’s key will be removed when you save.' : 'Encrypted before storage and never returned by the API.'}</small>
      <label htmlFor="provider-model">Model name</label>
      <input id="provider-model" placeholder="your-model-name" maxLength={255} required={!!preset}
        value={settings.model_name || ''} onChange={e => changeField('model_name', e.target.value)} />
      <small>{preset ? 'Ready to use. You can enter another model available to your account.' : 'Enter the model ID provided by your service.'}</small>
      <details className="provider-endpoint" open={!preset}>
        <summary>Endpoint settings{preset && <span>Filled in automatically</span>}</summary>
        <label htmlFor="provider-base-url">Base URL</label>
        <input id="provider-base-url" type="url" maxLength={2000} placeholder="https://your-provider.example/v1"
          value={settings.api_base_url || ''} onChange={e => changeEndpoint(e.target.value)} />
        <small>Use an OpenAI-compatible base URL. Changing the endpoint requires its own API key.</small>
      </details>
    </>}
  </fieldset>
}
