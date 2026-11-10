// Providers expose the Chat Completions API used by the backend. Keep defaults
// here so adding a preset does not change storage or existing custom endpoints.
// Official endpoint references are listed in docs/deployment.md.
export const PROVIDER_PRESETS = [
  {
    id: 'openai', label: 'OpenAI (ChatGPT)',
    baseUrl: 'https://api.openai.com/v1', model: 'gpt-5.4-mini',
    keyUrl: 'https://platform.openai.com/api-keys',
    help: 'Use an OpenAI API key from the developer dashboard.',
  },
  {
    id: 'anthropic', label: 'Anthropic (Claude)',
    baseUrl: 'https://api.anthropic.com/v1', model: 'claude-sonnet-4-6',
    keyUrl: 'https://platform.claude.com/settings/keys',
    help: 'Use a workspace API key from Claude Console.',
  },
  {
    id: 'gemini', label: 'Google Gemini',
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai', model: 'gemini-3.8-flash',
    keyUrl: 'https://aistudio.google.com/apikey',
    help: 'Use a Gemini API key from Google AI Studio.',
  },
  {
    id: 'openrouter', label: 'OpenRouter',
    baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto',
    keyUrl: 'https://openrouter.ai/settings/keys',
    help: 'Use an OpenRouter API key. Auto Router selects a model for each request.',
  },
  {
    id: 'groq', label: 'Groq',
    baseUrl: 'https://api.groq.com/openai/v1', model: 'openai/gpt-oss-120b',
    keyUrl: 'https://console.groq.com/keys',
    help: 'Use a GroqCloud API key.',
  },
]

export const normalizeProviderUrl = value => (value || '').trim().replace(/\/+$/, '')

export function providerSelection(settings) {
  // Draft-only overrides allow editing a preset's URL or disconnecting a
  // provider while its saved key still exists until the form is submitted.
  if (settings.provider_preset === 'custom') return 'custom'
  if (settings.provider_preset === 'local') return 'local'
  const preset = PROVIDER_PRESETS.find(item => item.baseUrl === normalizeProviderUrl(settings.api_base_url))
  if (preset) return preset.id
  return settings.api_base_url || settings.model_name || settings.gemini_api_key || settings.gemini_configured ? 'custom' : 'local'
}
